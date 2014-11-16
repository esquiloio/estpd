#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <openssl/rand.h>

#include "session.h"
#include "cipher.h"
#include "atomic.h"
#include "log.h"

static estp_session_t*  session_array;
static uint32_t         num_sessions;
static pthread_mutex_t  session_lock;
static in_addr_t        server_addr;
static in_addr_t        netmask;

TAILQ_HEAD(used_session_head_s, estp_session_s) used_session_head = TAILQ_HEAD_INITIALIZER(used_session_head);
TAILQ_HEAD(free_session_head_s, estp_session_s) free_session_head = TAILQ_HEAD_INITIALIZER(free_session_head);

#define LOCK    pthread_mutex_lock(&session_lock)
#define UNLOCK  pthread_mutex_unlock(&session_lock)

static void
used_session_put(estp_session_t* session)
{
    LOCK;
    TAILQ_INSERT_TAIL(&used_session_head, session, entry);
    UNLOCK;
}

static void
used_session_remove(estp_session_t* session)
{
    LOCK;
    TAILQ_REMOVE(&used_session_head, session, entry);
    UNLOCK;
}

static void
free_session_put(estp_session_t* session)
{
    LOCK;
    TAILQ_INSERT_TAIL(&free_session_head, session, entry);
    UNLOCK;
}

static estp_session_t*
free_session_get(void)
{
    estp_session_t* session;

    LOCK;
    session = TAILQ_FIRST(&free_session_head);
    if (!session) {
        UNLOCK;
        return NULL;
    }
    TAILQ_REMOVE(&free_session_head, session, entry);
    UNLOCK;

    return session;
}

static int32_t
session_ref_inc(estp_session_t* session)
{
    int32_t expect;
    int32_t desire;

    expect = session->ref_count;

    // Atomically increment the reference count
    do {
        // Negative reference count means session is not in use
        if (expect < 0)
            return -1;
        desire = expect + 1;
    } while (!ATOMIC_CAS(session->ref_count, expect, desire));

    return desire;
}

static int32_t
session_ref_dec(estp_session_t* session)
{
    int32_t expect;
    int32_t desire;

    expect = session->ref_count;

    // Atomically decrement the reference count.
    do {
        // Set the reference count to -1 if this is the last
        // reference and the free flag is set
        if (session->free_flag && expect == 1)
            desire = -1;
        else
            desire = expect - 1;
    } while (!ATOMIC_CAS(session->ref_count, expect, desire));

    return desire;
}

static void
session_free(estp_session_t* session)
{
    if (session->client_cipher) {
        cipher_free(session->client_cipher);
        session->client_cipher = NULL;
    }

    if (session->server_cipher) {
        cipher_free(session->server_cipher);
        session->server_cipher = NULL;
    }

    // Free the session ID by moving the next multiple handling wrap-around
    if (session->sid + num_sessions < session->sid)
        session->sid %= num_sessions;
    else
        session->sid += num_sessions;
}

estp_session_t*
estp_session_find(in_addr_t client_addr)
{
    return estp_session_get(ntohl(client_addr) - server_addr - 1);
}

estp_session_t*
estp_session_get(estp_sid_t sid)
{
    estp_session_t* session;

    session = &session_array[sid % num_sessions];
   
    if (session_ref_inc(session) < 0)
        return NULL;

    if (sid != session->sid) {
        session_ref_dec(session);
        return NULL;
    }

    return session;
}

estp_session_t*
estp_session_alloc(uint8_t cipher_type, cipher_keys_t* client_keys, cipher_keys_t* server_keys)
{
    estp_session_t* session;

    // Get a free session
    session = free_session_get();
    if (!session)
        return NULL;

    // Create a cipher for the client
    session->client_cipher = cipher_alloc(cipher_type, client_keys);
    if (!session->client_cipher) {
        free_session_put(session);
        return NULL;
    }

    // Create a cipher for the server
    session->server_cipher = cipher_alloc(cipher_type, server_keys);
    if (!session->server_cipher) {
        cipher_free(session->client_cipher);
        free_session_put(session);
        return NULL;
    }
   
    // Store cipher type
    session->cipher_type = cipher_type;

    // Reset the stats
    session->tx_packets = 0;
    session->rx_packets = 0;
    session->idle_rx_time = 0;
    session->last_rx_packets = 0;

    // Clear the free flag
    session->free_flag = false;

    // Put the session on the used list
    used_session_put(session);

    // Reset the reference count
    ATOMIC_SET(session->ref_count, 1);

    return session;
}

void
estp_session_free(estp_session_t* session)
{
    assert(session->ref_count > 0);

    session->free_flag = true;

    estp_session_unref(session);
}

void
estp_session_unref(estp_session_t* session)
{
    assert(session->ref_count > 0);

    if (session_ref_dec(session) == -1) {
        // Remove session from the used queue
        used_session_remove(session);

        // Free session resources
        session_free(session);

        // Put the session on the free list
        free_session_put(session);
    }
}

static void*
ageing_thread(void* info)
{
    estp_session_t* session;
    estp_session_t* next;

	pthread_detach(pthread_self());

    while (1) {
        sleep(AGEING_CHECK_PERIOD);

        LOCK;
        for (session = TAILQ_FIRST(&used_session_head);
             session != TAILQ_END(&used_session_head);
             session = next) {

            // Save the next pointer for the next iteration
            next = TAILQ_NEXT(session, entry);

            // Acquire a reference
            if (session_ref_inc(session) > 0) {
                if (session->rx_packets == session->last_rx_packets) {
                    session->idle_rx_time += AGEING_CHECK_PERIOD;

                    // Session is too old so free it
                    if (session->idle_rx_time >= 120) {
                        LOGX("ageing thread: freeing session id %d", session->sid);
                        session->free_flag = true;
                    }
                }
                else {
                    session->last_rx_packets = session->rx_packets;
                    session->idle_rx_time = 0;
                }

                // Release the reference.  If the reference is -1, then free it.
                if (session_ref_dec(session) == -1) {
                    // Remove session from the used queue
                    TAILQ_REMOVE(&used_session_head, session, entry);

                    // Free session resources
                    session_free(session);

                    // Put the session on the free list
                    TAILQ_INSERT_TAIL(&free_session_head, session, entry);
                }
            }

        }
        UNLOCK;
    }

    return NULL;
}

bool
estp_session_init(uint32_t _num_sessions, in_addr_t _server_addr, in_addr_t _netmask)
{
    estp_session_t*     session;
    in_addr_t           client_addr;
	pthread_t           tid;

    if (pthread_mutex_init(&session_lock, NULL) != 0)
        return false;

    num_sessions = _num_sessions;
    server_addr = ntohl(_server_addr);
    netmask = ntohl(_netmask);

    session_array = calloc(sizeof(estp_session_t), num_sessions);
    if (session_array == NULL)
        return false;

    // Determine the first client address
    client_addr = server_addr + 1;

    // Put all sessions on the free queue
    for (estp_sid_t sid = 0; sid < num_sessions; sid++) {
        session = &session_array[sid];

        session->sid = sid;
        session->client_addr = htonl(client_addr + sid);
        session->ref_count = -1;

        TAILQ_INSERT_TAIL(&free_session_head, session, entry);
    }

    // Start ageing thread
    if (pthread_create(&tid, NULL, ageing_thread, NULL) != 0)
        return false;

    return true;
}

