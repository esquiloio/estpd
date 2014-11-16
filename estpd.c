#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <getopt.h>
#include <semaphore.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "estp.h"
#include "inet.h"
#include "session.h"
#include "atomic.h"
#include "registry.h"
#include "log.h"

#define ETSP_CONTROL_TIMEOUT        5000

#define ETSP_MAX_THREADS            16

#define LOG(...)   warn(__VA_ARGS__)
#define LOGX(...)  warnx(__VA_ARGS__)
#define VLOGX(...) vwarnx(__VA_ARGS__)
#define ERR(...)    err(1, __VA_ARGS__)
#define ERRX(...)   errx(1, __VA_ARGS__)

///////////////////////////////////////////////////////////////////////////////
// Private Types
/////////////////////////////////////////////////////////////////////////////////
typedef struct
{
    int         tunfd;
    int         dgramfd;
} data_params_t;

typedef struct
{
    int         hellofd;
    SSL_CTX*    ctx;
    sem_t*      thread_count;
} hello_params_t;
///////////////////////////////////////////////////////////////////////////////
// Private Variables
/////////////////////////////////////////////////////////////////////////////////
static struct config_s {
    uint16_t    port;
    char*       cert;
    char*       key;
    char*       cacert;
    in_addr_t   server_addr;
    in_addr_t   netmask;
    uint16_t    mtu;
    uint8_t     rx_threads;
    uint8_t     tx_threads;
    uint8_t     hello_threads;
    uint32_t    sessions;
} config;

static pthread_mutex_t* mutex_buf;

///////////////////////////////////////////////////////////////////////////////
// Private Functions
/////////////////////////////////////////////////////////////////////////////////
static int
tun_alloc(char* dev)
{
    struct ifreq ifr;
    int fd;
    int err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        return fd;

    bzero(&ifr, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (err < 0) {
        close(fd);
        return err;
    }

    strncpy(dev, ifr.ifr_name, IFNAMSIZ);

    return fd;
}

#if 0
static int
ssl_verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert) {
        X509_NAME* sname = X509_get_subject_name(cert);
        X509_NAME_print_ex_fp(stdout, sname, 0, 0);
        printf("\n");
    }

    return preverify;
}
#endif

static void
ssl_locking_function(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&mutex_buf[n]);
	else
		pthread_mutex_unlock(&mutex_buf[n]);
}

static unsigned long
ssl_id_function(void)
{
	return (unsigned long) pthread_self();
}

static SSL_CTX*
ssl_init(void)
{
    SSL_CTX* ctx;

	mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (!mutex_buf)
		ERR("ssl init:");
	for (int i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&mutex_buf[i], NULL);

	CRYPTO_set_id_callback(ssl_id_function);
	CRYPTO_set_locking_callback(ssl_locking_function);

    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLSv1_server_method());
    if (!ctx)
        ERRSSL("ssl init: ctx new");

    if (SSL_CTX_use_certificate_file(ctx, config.cert, SSL_FILETYPE_PEM) != 1)
        ERRSSL("ssl init: %s", config.cert);

    if (SSL_CTX_use_PrivateKey_file(ctx, config.key, SSL_FILETYPE_PEM) != 1)
        ERRSSL("ssl init: %s", config.key);

    if (SSL_CTX_check_private_key(ctx) != 1)
        ERRSSL("ssl init: key check");

    if (SSL_CTX_load_verify_locations(ctx, config.cacert, NULL) != 1)
        ERRSSL("ssl init: %s", config.cacert);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    if (SSL_CTX_set_cipher_list(ctx, "AES128-SHA:AES256-SHA") != 1)
        ERRSSL("ssl init: cipher list");

    return ctx;
}

static int
ssl_read_exactly(SSL* ssl, void* buf, size_t len)
{
    int nread;

    while (len > 0) {
        nread = SSL_read(ssl, buf, len);
        if (nread < 0)
            return nread;
        len -= nread;
        buf += nread;
    }

    return 0;
}

static bool
check_header(estp_header_t* header)
{
    // Check that the version is supported
    if (header->version > ESTP_VERSION) {
        LOGX("header: unsupported version 0x%x", header->version);
        return false;
    }

    // Check packet type
    if (header->type >= ESTP_TYPE_MAX){
        LOGX("header: unknown packet type %d", header->type);
        return false;
    }

    return true;
}


static void
usage(const char* format, ...)
{
    va_list args;

    if (format) {
        va_start(args, format);
        VLOGX(format, args);
        va_end(args);
    }

    fprintf(stderr,
        "Usage: estpd [OPTION...]\n"
    );
    exit(1);
}

static void
parse_opts(int argc, char* argv[])
{
    while (1) {
        char c;
        int optidx = 0;
        static struct option opts[] = {
            { "port",           required_argument, 0,  'p' },
            { "cert",           required_argument, 0,  'c' },
            { "key",            required_argument, 0,  'k' },
            { "cacert",         required_argument, 0,  'a' },
            { "address",        required_argument, 0,  'i' },
            { "netmask",        required_argument, 0,  'n' },
            { "mtu",            required_argument, 0,  'm' },
            { "sessions",       required_argument, 0,  's' },
            { "rxthreads",      required_argument, 0,  'r' },
            { "txthreads",      required_argument, 0,  't' },
            { "hellothreads",   required_argument, 0,  'l' },
            { "help",           no_argument,       0,  'h' },
            { 0,                0,                 0,  0   }
        };

        c = getopt_long(argc, argv, "p:c:k:r:a:n:s:r:t:l:h", opts, &optidx);
        if (c == -1)
            break;

        switch (c) {
            case 'p':
                config.port = atoi(optarg);
                break;
            case 'c':
                config.cert = strdup(optarg);
                break;
            case 'k':
                config.key = strdup(optarg);
                break;
            case 'a':
                config.cacert = strdup(optarg);
                break;
            case 'i':
                if (inet_pton(AF_INET, optarg, &config.server_addr) != 1)
                    usage("invalid IP address '%s'", optarg);
                break;
            case 'n':
                if (inet_pton(AF_INET, optarg, &config.netmask) != 1)
                    usage("invalid netmask '%s'", optarg);
                break;
            case 'm':
                config.mtu = atoi(optarg);
                if (config.mtu > ESTP_MTU_MAX || config.mtu < ESTP_MTU_MIN)
                    usage("mtu %d not in the allowed range %d to %d", optarg, ESTP_MTU_MIN, ESTP_MTU_MAX);
                break;
            case 's':
                config.sessions = atoi(optarg);
                if (config.sessions <= 0)
                    usage("invalid number of sessions '%s'", optarg);
                break;
            case 'r':
                config.rx_threads = atoi(optarg);
                if (config.rx_threads > ETSP_MAX_THREADS || config.rx_threads <= 0)
                    usage("invalid number of threads '%s'", optarg);
                break;
            case 't':
                config.tx_threads = atoi(optarg);
                if (config.tx_threads > ETSP_MAX_THREADS || config.tx_threads <= 0)
                    usage("invalid number of threads '%s'", optarg);
                break;
            case 'l':
                config.hello_threads = atoi(optarg);
                if (config.hello_threads > ETSP_MAX_THREADS || config.hello_threads <= 0)
                    usage("invalid number of threads '%d'", optarg);
                break;
            default:
                usage(NULL);
                break;
        }
    }

    // Check for non-options
    if (optind < argc)
        usage("excess parameters on command line");
}

static void
tx_close_packet(int dgramfd, sockaddr_t* peer_addr, socklen_t socklen, estp_sid_t sid)
{
    estp_header_t   header;
    char            ipstr[INET_ADDRSTRLEN];

    // Fill in the ESTP header
    header.type = ESTP_TYPE_CLOSE;
    header.version = ESTP_VERSION;
    header.length = 0;
    header.sid = sid;

    // Send the packet to our peer
    LOGX("tx close packet: session id %d peer IP %s", sid,
         inet_ntop(AF_INET, &peer_addr->sin.sin_addr, ipstr, sizeof(ipstr)));
    LOGBLOB("tx dgram", (uint8_t*) &header, sizeof(header));
    if (sendto(dgramfd, &header, sizeof(header), 0, (struct sockaddr*)peer_addr, socklen) < 0) {
        LOG("tx close packet: sendto");
    }
}

static void
tx_data_packet(int dgramfd, int tunfd)
{
    ssize_t         data_size;
    estp_packet_t   packet;
    estp_session_t* session = NULL;
    ip_header_t*    iphdr;
    size_t          iv_size;
    size_t          block_size;
    size_t          pad_size;
    size_t          packet_size;
    uint8_t         iv[CIPHER_MAX_IV_LEN];

    // Read a packet from the tunnel
    data_size= read(tunfd, packet.data, sizeof(packet.data));
    if (data_size < 0) {
        LOG("tx thread: read");
        goto fail;
    }

    LOGBLOB("rx tun", packet.data, data_size);

    // Check the MTU
    if (data_size > config.mtu) {
        LOGX("tx thread: packet length %zd exceeds MTU %d", data_size, config.mtu);
        goto fail;
    }

    // Make sure it's an IP packet
    iphdr = (ip_header_t*) &packet.data;
    if (data_size < sizeof(ip_header_t) || iphdr->ver_ihl != 0x45) {
        LOGX("tx thread: not an IP packet");
        goto fail;
    }

    // Find the session based on the destintation IP address
    session = estp_session_find(iphdr->dest);
    if (!session) {
        LOGX("tx thread: no session for 0x%x", iphdr->dest);
        goto fail;
    }

    // Make sure we have an IP address for the tunnel peer
    if (!session->peer_addr.sin.sin_addr.s_addr) {
        LOGX("tx thread: no peer for session id %d", session->sid);
        goto fail;
    }

    // Fill in the ESTP header
    packet.header.type = ESTP_TYPE_DATA;
    packet.header.version = ESTP_VERSION;
    packet.header.length = htons(data_size);
    packet.header.sid = session->sid;

    // Determine sizes
    iv_size = cipher_iv_size(session->cipher_type);
    block_size = cipher_block_size(session->cipher_type);
    pad_size = (block_size - (data_size % block_size)) % block_size;

    // Pad the packet with zeros if needed
    if (pad_size) {
        bzero(&packet.data[data_size], pad_size);
    }

    // Generate a random IV
    RAND_pseudo_bytes(iv, iv_size);

    // Encrypt the data portion
    packet_size = data_size + pad_size;
    if (!cipher_encrypt(session->server_cipher, iv, packet.data, packet_size)) {
        LOGX("tx thread: encryption failed");
        goto fail;
    }

    // Copy the IV to the packet
    memcpy(packet.data + packet_size, iv, iv_size);

    // Calculate the MAC over the entire packet
    packet_size += sizeof(packet.header) + iv_size;
    cipher_mac_calc(session->server_cipher, (void*)&packet + packet_size, &packet, packet_size);
    packet_size += cipher_mac_size(session->cipher_type);
    
    // Send the packet to our peer
    LOGBLOB("tx dgram", (uint8_t*) &packet, packet_size);
    if (sendto(dgramfd, &packet, packet_size, 0, (struct sockaddr*)&session->peer_addr,
               sizeof(session->peer_addr)) < 0) {
        LOG("tx thread: sendto");
        goto fail;
    }

    ATOMIC_INC(session->tx_packets);

fail:
    if (session)
        estp_session_unref(session);
}

static void*
tx_thread(void* info)
{
    data_params_t*  params = info;

	pthread_detach(pthread_self());

    while (1) {
        tx_data_packet(params->dgramfd, params->tunfd);
    }

    return NULL;
}

static void
rx_data_packet(estp_session_t* session, int tunfd, estp_packet_t* packet, size_t packet_size)
{
    ip_header_t*    iphdr;
    size_t          iv_size;
    size_t          block_size;
    size_t          data_size;
    size_t          mac_size;
    size_t          packet_left;

    // Get sizes
    data_size = htons(packet->header.length);
    mac_size = cipher_mac_size(session->cipher_type);
    iv_size = cipher_iv_size(session->cipher_type);
    block_size = cipher_block_size(session->cipher_type);

    // Make sure the packet includes at least the MAC, IV, and IP header
    if (packet_size < mac_size + iv_size + sizeof(ip_header_t)) {
        LOGX("rx thread: short packet size %zd", packet_size);
        goto fail;
    }

    // Remove MAC from leftover count
    packet_left = packet_size - mac_size;

    // Verify the entire packet with the attached MAC
    if (!cipher_mac_verify(session->client_cipher,
                           (void*)packet + packet_left,
                           (void*)packet, packet_left)) {
        LOGX("rx thread: mac verify failed for session %d", session->sid);
        goto fail;
    }

    // Remove header and IV from leftover count
    packet_left -= sizeof(packet->header) + iv_size;

    // Check the data size is less than the MTU
    if (data_size > config.mtu) {
        LOGX("rx thread: packet size %zd exceeds MTU %d", data_size, config.mtu);
        goto fail;
    }

    // Make sure the data size doesn't exceed what we have left
    if (data_size > packet_left) {
        LOGX("rx thread: invalid size for data packet %zd", data_size);
        goto fail;
    }

    // The data must be a multiple of the cipher block size
    if (packet_left % block_size != 0) {
        LOGX("rx thread: data packet packet size %zd not block multiple", packet_left);
        goto fail;
    }

    // Decrypt the packet
    if (!cipher_decrypt(session->client_cipher, packet->data + packet_left, packet->data, packet_left)) {
        LOGX("rx thread: decryption failed");
        goto fail;
    }

    // Check that the IP version is supported
    iphdr = (ip_header_t*) &packet->data;
    if (data_size < sizeof(ip_header_t)) {
        LOGX("rx thread: short IP header %zd", packet_size);
        goto fail;
    }

    // Check that the packet is IPv4
    if ((iphdr->ver_ihl & 0xf0) != 0x40) {
        LOGX("rx thread: header not IPv4");
        goto fail;
    }

    // Check that the IP source matches the session
    if (session->client_addr != iphdr->src) {
        LOGX("rx thread: invalid source IP address 0x%x", ntohl(iphdr->src));
        goto fail;
    }

    LOGBLOB("tx tun", packet->data, data_size);

    // Forward the packet to the tunnel
    if (write(tunfd, packet->data, data_size) < 0) {
        LOG("rx thread: write");
        goto fail;
    }
fail:
    return;
}

static void
rx_packet(int dgramfd, int tunfd)
{
    estp_packet_t   packet;
    ssize_t         packet_size;
    estp_session_t* session = NULL;
    sockaddr_t      from_addr;
    socklen_t       socklen;

    socklen = sizeof(from_addr);

    // Read the ESTP header
    if ((packet_size = recvfrom(dgramfd, &packet, sizeof(packet), 0,
                                (struct sockaddr*) &from_addr, &socklen)) < 0) {
        LOG("rx thread: recvfrom");
        goto fail;
    }

    LOGBLOB("rx dgram", (uint8_t*) &packet, packet_size);

    // Check the length
    if (packet_size < sizeof(packet.header)) {
        LOGX("rx thread: short packet header %zd", packet_size);
        goto fail;
    }

    // Check the ESTP header
    if (!check_header(&packet.header)) {
        LOGX("rx thread: bad header");
        goto fail;
    }

    // Get the session record
    session = estp_session_get(packet.header.sid);
    if (!session) {
        tx_close_packet(dgramfd, &from_addr, socklen, packet.header.sid);
        LOGX("rx thread: no session found for sid %d", packet.header.sid);
        goto fail;
    }

    ATOMIC_INC(session->rx_packets);

    // Save the peer address if it is not set
    if (!session->peer_addr.sin.sin_addr.s_addr)
        session->peer_addr = from_addr;

    switch (packet.header.type) {
        case ESTP_TYPE_KEEPALIVE: {
            break;
        }
        case ESTP_TYPE_DATA: {
            rx_data_packet(session, tunfd, &packet, packet_size);
            break;
        }
        default: {
            break;
        }
    }

fail:
    if (session)
        estp_session_unref(session);
}

static void*
rx_thread(void* info)
{
    data_params_t*  params = info;

	pthread_detach(pthread_self());

    while (1) {
        rx_packet(params->dgramfd, params->tunfd);
    }

    return NULL;
}

static void
hello_exchange(int hellofd, SSL_CTX* ctx)
{
    estp_session_t* session = NULL;
    SSL*            ssl = NULL;
    estp_packet_t   packet;
    size_t          keys_size;
    cipher_keys_t   server_keys;
    size_t          packet_len;
    size_t          hello_size;
    X509*           peer_cert;
    X509_NAME*      peer_name;
    char            peer_cn[20];
    char            ipstr[INET_ADDRSTRLEN];

    // Set a socket timeout so we don't wait too long
    if (sock_timeout(hellofd, ETSP_CONTROL_TIMEOUT) < 0) {
        LOGX("hello thread: sock timeout");
        goto fail;
    }

    // Allocate SSL session
    if ((ssl = SSL_new(ctx)) == NULL) {
        LOGSSL("hello thread: ssl new");
        goto fail;
    }

    // Attach socket to SSL session
    if (SSL_set_fd(ssl, hellofd) != 1) {
        LOGSSL("hello thread: set fd");
        goto fail;
    }

    // Complete SSL handshake
    if (SSL_accept(ssl) != 1) {
        LOGSSL("hello thread: ssl accept");
        goto fail;
    }

    // Get the peer SSL certificate
    if ((peer_cert = SSL_get_peer_certificate(ssl)) == NULL) {
        LOGSSL("hello thread: unable to get peer cert");
        goto fail;
    }

    // Check certificate verification
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        LOGSSL("hello thread: peer cert failed to verify");
        goto fail;
    }

    // Read ESTP packet header
    if (ssl_read_exactly(ssl, &packet.header, sizeof(packet.header)) < 0) {
        LOG("hello thread: ssl read header");
        goto fail;
    }

    // Check ESTP packet header
    if (!check_header(&packet.header)) {
        LOGX("hello thread: bad header");
        goto fail;
    }

    // We are only expecting a client hello ESTP packet
    if (packet.header.type != ESTP_TYPE_CLIENT_HELLO) {
        LOGX("hello thread: unexpected packet type %d", packet.header.type);
        goto fail;
    }

    // Make sure the length is correct for a client hello
    hello_size = htons(packet.header.length);
    if (hello_size > sizeof(packet.client_hello) ||
        hello_size < offsetof(struct client_hello_s, cipher_keys)) {
        LOGX("hello thread: incorrect length for hello packet %zd", hello_size);
        goto fail;
    }

    // Read client hello payload
    if (ssl_read_exactly(ssl, &packet.client_hello, hello_size) < 0) {
        LOG("hello thread: ssl read client hello");
        goto fail;
    }

    // Get the cipher key size
    if ((keys_size = cipher_keys_size(packet.client_hello.cipher_type)) == 0) {
        LOGX("hello thread: invalid cipher type %d", packet.client_hello.cipher_type);
        goto fail;
    }

    // Make sure we have the correct packet size
    if (hello_size != keys_size + offsetof(struct client_hello_s, cipher_keys)) {
        LOGX("hello thread: invalid client hello length %zd", hello_size);
        goto fail;
    }

    // Generate random keys for the server
    if (RAND_bytes((void*)&server_keys, keys_size) != 1) {
        if (RAND_pseudo_bytes((void*)&server_keys, keys_size) != 1) {
            LOGX("hello thread: unable to generate server keys");
            goto fail;
        }
    }

    // Allocate a session for the client
    if ((session = estp_session_alloc(packet.client_hello.cipher_type,
                                      &packet.client_hello.cipher_keys,
                                      &server_keys)) == NULL) {
        LOGX("hello thread: cannot allocate session");
        goto fail;
    }

    // Send a server hello packet in response
    packet_len = offsetof(struct server_hello_s, cipher_keys) + keys_size;
    packet.header.type = ESTP_TYPE_SERVER_HELLO;
    packet.header.version = ESTP_VERSION;
    packet.header.length = htons(packet_len);
    packet.header.sid = session->sid;

    packet.server_hello.client_ip = session->client_addr;
    packet.server_hello.server_ip = config.server_addr;
    packet.server_hello.netmask = config.netmask;
    packet.server_hello.mtu = htons(config.mtu);
    packet.server_hello.cipher_type = cipher_get_type(session->server_cipher);
    memcpy(&packet.server_hello.cipher_keys, &server_keys, keys_size);

    // Write server hello packet
    if (SSL_write(ssl, &packet, sizeof(packet.header) + packet_len) < 0) {
        LOGX("hello thread: ssl write");
        goto fail;
    }

    LOGX("hello thread: allocated session id %d for client IP %s",
          session->sid, inet_ntop(AF_INET, &session->client_addr, ipstr, sizeof(ipstr)));

    // Register certificate common name and client IP
    if ((peer_name = X509_get_subject_name(peer_cert)) == NULL)
        LOGX("hello thread: cert subject name not found");
    else if (X509_NAME_get_text_by_NID(peer_name, NID_commonName, peer_cn, sizeof(peer_cn)) < 0)
        LOGX("hello thread: cert common name not found");
    else if (!estp_registry_add(session->client_addr, peer_cn))
        LOGX("hello thread: unable to add '%s' to registry", peer_cn);
    else
        LOGX("hello thread: registered name '%s' to client IP %s",
              peer_cn, inet_ntop(AF_INET, &session->client_addr, ipstr, sizeof(ipstr)));

    estp_session_unref(session);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(hellofd);

    return;

fail:
    if (session)
        estp_session_free(session);

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(hellofd);
}

static void*
hello_thread(void* info)
{
    hello_params_t* params = info;

	pthread_detach(pthread_self());

    // Process the hello exchange
    hello_exchange(params->hellofd, params->ctx);

    // Increment the thread count
    sem_post(params->thread_count);

    // Free the params 
    free(params);

    return NULL;
}

static void
listen_thread(void *info)
{
    sem_t           thread_count;
    pthread_t       tid;
    hello_params_t* params;
    int             listenfd;
    SSL_CTX*        ctx;

    // Initialize a semaphore to count hello threads
    if (sem_init(&thread_count, 0, config.hello_threads) < 0)
        ERR("listen thread: sem init");

    // Initialize the SSL context
    ctx = ssl_init();

    // Open socket to listen for client hello requests
    listenfd = listen_socket(config.port);
    if (listenfd < 0)
        ERR("listen thread: socket");

    while (1) {
        if (sem_wait(&thread_count) < 0)
            ERR("listen thread: sem wait");

        if ((params = malloc(sizeof(*params))) == NULL) {
            LOG("listen thread: malloc");
        }
        else {
            params->ctx = ctx;
            params->thread_count = &thread_count;
            if ((params->hellofd = accept(listenfd, NULL, 0)) < 0) {
                free(params);
                LOG("listen_thread: accept");
            }
            else if (pthread_create(&tid, NULL, hello_thread, params) != 0) {
                close(params->hellofd);
                free(params);
                LOG("listen thread: pthread create");
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Main
///////////////////////////////////////////////////////////////////////////////
int
main(int argc, char* argv[])
{
    char            dev[IFNAMSIZ];
	pthread_t       tid;
    data_params_t   params;

    // TODO: Parse config file options

    // Parse command line options
    parse_opts(argc, argv);

    // Set defaults for unspecified options
    if (!config.port)
        config.port = ESTP_DEFAULT_PORT;
    if (!config.cert)
        config.cert = strdup("/etc/estpd/cert.pem");
    if (!config.key)
        config.key = strdup("/etc/estpd/key.pem");
    if (!config.cacert)
        config.cacert = strdup("/etc/estpd/cacert.pem");
    if (!config.server_addr)
        config.server_addr = htonl(0xac100001);
    if (!config.netmask)
        config.netmask = htonl(0xffff0000);
    if (!config.mtu)
        config.mtu = ESTP_MTU_MAX;
    if (!config.sessions)
        config.sessions = 1000;
    if (!config.rx_threads)
        config.rx_threads = 1;
    if (!config.tx_threads)
        config.tx_threads = 1;
    if (!config.hello_threads)
        config.hello_threads = 1;

    // Allocate the tunnel interface
    params.tunfd = tun_alloc(dev);
    if (params.tunfd < 0)
        ERR("tunnel alloc");

    LOGX("using tunnel interface %s", dev);

    // Open the tunnel data socket
    params.dgramfd = dgram_socket(config.port);
    if (params.dgramfd < 0)
        ERR("dgram socket");

    // Set the tunnel IP address, netmask, and MTU
    if (ifconfig(params.dgramfd, dev, config.server_addr, config.netmask, config.mtu) < 0)
        ERR("tunnel ip address");

    // Initialize the session interface
    if (!estp_session_init(config.sessions, config.server_addr, config.netmask))
        ERRX("unable to initialize sessions");

    // Start tx threads
    if (pthread_create(&tid, NULL, tx_thread, &params) != 0)
        ERR("pthread create");

    // Start rx threads
    if (pthread_create(&tid, NULL, rx_thread, &params) != 0)
        ERR("pthread create");

    // Run the listen thread
    listen_thread(NULL);

    return EX_OK;
}

