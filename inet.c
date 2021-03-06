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
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "inet.h"

int
sock_timeout(int sockfd, uint32_t milliseconds)
{
    struct timeval tv;
    int err;

    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = milliseconds % 1000 * 1000;

    err = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (err != 0)
        return err;

    err = setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (err != 0)
        return err;

    return 0;
}

int
ifconfig(int fd, const char* dev, in_addr_t addr, in_addr_t netmask, uint16_t mtu)
{
    struct ifreq ifr;
    struct sockaddr_in* sin;
    int err;
    
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    sin = (struct sockaddr_in*)&ifr.ifr_addr;
    sin->sin_family = AF_INET;

    sin->sin_addr.s_addr = addr;
    err = ioctl(fd, SIOCSIFADDR, &ifr);
    if (err < 0)
        return err;

    sin->sin_addr.s_addr = netmask;
    err = ioctl(fd, SIOCSIFNETMASK, &ifr);
    if (err < 0)
        return err;

    ifr.ifr_mtu = mtu;
    err = ioctl(fd, SIOCSIFMTU, (void *) &ifr);
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
    int optval;

    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return sockfd;

    optval = 1;
    err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (err != 0)
        return err;

    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    err = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0)
        return err;

    return sockfd;
}

int
listen_socket(int port)
{
    int sockfd;
    int err;
    struct sockaddr_in addr;
    int optval;

    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return sockfd;

    optval = 1;
    err = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (err != 0)
        return err;

    bzero(&addr,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    err = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0)
        return err;

    err = listen(sockfd, 64);
    if (err < 0)
        return err;

    return sockfd;
}


