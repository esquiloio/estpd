/*
 * Esquilo Secure Tunneling Protocol Daemon (ESTP)
 * 
 * Copyright 2014-2018 Esquilo Corporation - https://esquilo.io/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define ESTP_DEFAULT_PORT       1190

#define COOKIE_SECRET_LENGTH 16

uint8_t cookie_secret[COOKIE_SECRET_LENGTH];

int
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

int
ip_addr(int fd, const char* dev, const char* addr, const char* netmask)
{
    struct ifreq ifr;
    struct sockaddr_in* sin;
    int err;
    
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    ifr.ifr_addr.sa_family = AF_INET;
    inet_pton(AF_INET, addr, &sin->sin_addr);
    err = ioctl(fd, SIOCSIFADDR, &ifr);
    if (err < 0)
        return err;

    inet_pton(AF_INET, netmask, &sin->sin_addr);
    err = ioctl(fd, SIOCSIFNETMASK, &ifr);
    if (err < 0)
        return err;

    err = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (err < 0)
        return err;

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    return ioctl(fd, SIOCSIFFLAGS, &ifr);
}

int
dgram_socket(int port)
{
    int sockfd;
    int err;
    struct sockaddr_in addr;
    const int on = 1;

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return sockfd;

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));

    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    err = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0)
        return err;

    return sockfd;
}

void
print_packet(ssize_t len, uint8_t* packet)
{
    int i;

    printf("len %zd\n", len);
    for (i = 0; i < len; i++) {
        printf(" %02x", packet[i]);
        if (i % 16 == 15)
            printf("\n");
    }
    if (i % 16 != 0)
        printf("\n");
}

int
verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
   
    printf("verify depth %d error %d\n", depth, err);

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (cert) {
        X509_NAME* iname = X509_get_issuer_name(cert);
        printf("Issuer:");
        X509_NAME_print_ex_fp(stdout, iname, 0, 0);
        printf("\n");
        printf("Subject:");
        X509_NAME* sname = X509_get_subject_name(cert);
        X509_NAME_print_ex_fp(stdout, sname, 0, 0);
        printf("\n");
    }

    return preverify;
}

static int
hmac_cookie(SSL* ssl, unsigned char* result, unsigned int* result_len)
{
    unsigned int buffer_len = sizeof(struct in_addr) + sizeof(in_port_t);
    unsigned char buffer[buffer_len];
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in sin;
    } peer;

    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    if (peer.ss.ss_family != AF_INET)
        return 0;

    memcpy(buffer, &peer.sin.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.sin.sin_port), &peer.sin.sin_addr, sizeof(struct in_addr));

    HMAC(EVP_sha1(), cookie_secret, COOKIE_SECRET_LENGTH,
         buffer, buffer_len, result, result_len);

    return 1;
}

static int
generate_cookie(SSL* ssl, unsigned char *cookie, unsigned int* cookie_len)
{
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    fprintf(stderr, "%s\n", __FUNCTION__);

    if (hmac_cookie(ssl, result, &result_len) != 1)
        return 0;

    memcpy(cookie, result, result_len);
    *cookie_len = result_len;

    return 1;
}

static int
verify_cookie(SSL* ssl, unsigned char* cookie, unsigned int cookie_len)
{
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    fprintf(stderr, "%s\n", __FUNCTION__);

    if (hmac_cookie(ssl, result, &result_len) != 1)
        return 0;

    if (cookie_len != result_len || memcmp(result, cookie, result_len) != 0)
        return 0;

    return 1;
}

int
main(int argc, char* argv[])
{
    int tunfd;
    int listenfd;
    int sessionfd;
    char dev[IFNAMSIZ];
    uint8_t packet[1500];
    SSL_CTX* ctx;
    SSL* ssl = NULL;
    struct pollfd fds[3];
    const char* certfile = "cert.pem";
    const char* keyfile = "key.pem";
    const char* cafile = "cacert.pem";

    tunfd = tun_alloc(dev);
    if (tunfd < 0)
        err(EX_IOERR, "tunnel alloc");

    printf("using tunnel interface %s\n", dev);

    listenfd = dgram_socket(ESTP_DEFAULT_PORT);
    if (listenfd < 0)
        err(EX_IOERR, "listen socket");

    if (ip_addr(listenfd, dev, "172.16.0.1", "255.255.255.0") < 0)
        err(EX_IOERR, "tunnel ip address");

    SSL_library_init();
    SSL_load_error_strings();

    if (RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH) != 1)
        errx(EX_IOERR, "cookie random: %s", ERR_error_string(ERR_get_error(), NULL));

    ctx = SSL_CTX_new(DTLSv1_server_method());
    if (!ctx)
        errx(EX_IOERR, "ctx new: %s", ERR_error_string(ERR_get_error(), NULL));

    if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1)
        errx(EX_IOERR, "%s: %s", certfile, ERR_error_string(ERR_get_error(), NULL));

    if (SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1)
        errx(EX_IOERR, "%s: %s", certfile, ERR_error_string(ERR_get_error(), NULL));

    if (SSL_CTX_check_private_key(ctx) != 1)
        errx(EX_IOERR, "key check: %s", ERR_error_string(ERR_get_error(), NULL));

    if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1)
        errx(EX_IOERR, "%s: %s", cafile, ERR_error_string(ERR_get_error(), NULL));

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 1);

    SSL_CTX_set_read_ahead(ctx, 1);

    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

    fds[0].fd = tunfd;
    fds[0].events = POLLIN;
    fds[1].fd = listenfd;
    fds[1].events = POLLIN;
    fds[2].fd = -1;
    fds[2].events = POLLIN;

    while (1) {
        ssize_t len;
        int numfds;

        numfds = poll(fds, 3, -1);
        if (numfds < 0)
            err(EX_IOERR, "poll");

        fprintf(stderr, "poll %d\n", numfds);

        if (fds[0].revents) {
            fprintf(stderr, "tunfd POLLIN\n");

            len = read(tunfd, packet, sizeof(packet));
            if (len < 0)
                err(EX_IOERR, "tunnel read");
            print_packet(len, packet);

            if (ssl) {
                if (SSL_write(ssl, packet, len) < 0)
                    errx(EX_IOERR, "ssl write: %s", ERR_error_string(ERR_get_error(), NULL));
            }
        }

        if (!ssl && fds[1].revents) {
            struct timeval timeout;
            BIO *bio;
            union {
                struct sockaddr_storage ss;
                struct sockaddr_in sin;
            } client_addr;
            
            fprintf(stderr, "listenfd POLLIN\n");

            bzero(&client_addr, sizeof(client_addr));

            bio = BIO_new_dgram(listenfd, BIO_NOCLOSE);

            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            ssl = SSL_new(ctx);

            SSL_set_bio(ssl, bio, bio);
            SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

            if (DTLSv1_listen(ssl, &client_addr) != 1) 
                errx(EX_IOERR, "listen: %s", ERR_error_string(ERR_get_error(), NULL));

            sessionfd = dgram_socket(ESTP_DEFAULT_PORT);
            if (sessionfd < 0)
                err(EX_IOERR, "session socket");

            fprintf(stderr, "connect to 0x%x port %d\n",
                    ntohl(client_addr.sin.sin_addr.s_addr),
                    ntohs(client_addr.sin.sin_port));

            if (connect(sessionfd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in)) < 0)
                err(EX_IOERR, "session connect");

	        BIO_set_fd(SSL_get_rbio(ssl), sessionfd, BIO_NOCLOSE);
	        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);

            if (SSL_accept(ssl) != 1)
                errx(EX_IOERR, "ssl accept: %s", ERR_error_string(ERR_get_error(), NULL));

     	    timeout.tv_sec = 5;
	        timeout.tv_usec = 0;
	        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

            fds[2].fd = sessionfd;
        }

        if (fds[2].revents) {
            fprintf(stderr, "sessionfd POLLIN\n");

            if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                fprintf(stderr, "ssl shutdown\n");
                SSL_shutdown(ssl);
                close(sessionfd);
                SSL_free(ssl);
                ssl = NULL;
                sessionfd = -1;
            }
            else {
                len = SSL_read(ssl, packet, sizeof(packet));
                if (len < 0)
                    errx(EX_IOERR, "ssl read: %s", ERR_error_string(ERR_get_error(), NULL));
                print_packet(len, packet);
                len = write(tunfd, packet, len);
                if (len < 0)
                    err(EX_IOERR, "tunnel write");
            }
        }
    }

    return EX_OK;
}

