#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "registry.h"
#include "log.h"

#define SERVER_SOCKET_PATH "/var/run/estpd/estpd_server.socket"
#define CLIENT_SOCKET_PATH "/var/run/estpd/estpd_client.socket"

#define TYPE_LEN 3
#define MAC_ADDRSTRLEN 17

static int sock = -1;
static struct sockaddr_un server_address;
static struct sockaddr_un client_address;

static bool
send_message(char* buffer)
{
    if (sock < 0 && !estp_registry_init()) {                                                                        
        LOG("Init error");                                                                                          
        return false;                                                                                               
    }                                                                                                               
                                                                                                                    
    if (sendto(sock, buffer, strlen(buffer), 0,                                                                     
        (const struct sockaddr*)&client_address, sizeof(client_address)) < 0) {                                     
        LOG("Send error");                                                                                          
        return false;                                                                                               
    }

    return true;
}

bool
estp_registry_init()
{
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, SERVER_SOCKET_PATH);
    client_address.sun_family = AF_UNIX;
    strcpy(client_address.sun_path, CLIENT_SOCKET_PATH);

    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG("Socket create error");
        return false;
    }

    unlink(SERVER_SOCKET_PATH);

    if (bind(sock, (struct sockaddr *) &server_address, sizeof(struct sockaddr_un))) {
        LOG("Socket bind error");
        return false;
    }

    return true;
}

void
estp_registry_shutdown()
{
    unlink(SERVER_SOCKET_PATH);
    close(sock);
}

bool
estp_registry_add(in_addr_t address, const char* name)
{
    char buffer[TYPE_LEN + MAC_ADDRSTRLEN + INET_ADDRSTRLEN + 3]; // 3 = 2 separators + null termination
    strncpy(buffer, "add,", TYPE_LEN + 1); 

    strncpy(&buffer[TYPE_LEN + 1], name, MAC_ADDRSTRLEN);
    buffer[TYPE_LEN + 1 + MAC_ADDRSTRLEN] = ',';
    inet_ntop(AF_INET, &address, &buffer[TYPE_LEN + 1 + MAC_ADDRSTRLEN + 1],
              sizeof(buffer) - (TYPE_LEN + 1 + MAC_ADDRSTRLEN + 1));
    buffer[sizeof(buffer) - 1] = '\0';

    return send_message(buffer);
}

bool
estp_registry_del(in_addr_t address)
{
    char buffer[TYPE_LEN + INET_ADDRSTRLEN + 3]; // 3 = 2 separators + null termination
    strncpy(buffer, "del,,", TYPE_LEN + 2); 

    inet_ntop(AF_INET, &address, &buffer[TYPE_LEN + 2],
              sizeof(buffer) - (TYPE_LEN + 2));
    buffer[sizeof(buffer) - 1] = '\0';

    return send_message(buffer);
}
