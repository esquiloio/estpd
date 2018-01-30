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
#pragma once

#include <stdio.h>
#include <err.h>

#define DEBUG(...)      warn(__VA_ARGS__)
#define DEBUGX(...)     warnx(__VA_ARGS__)
#define VDEBUGX(...)    vwarnx(__VA_ARGS__)

#define LOG(...)        warn(__VA_ARGS__)
#define LOGX(...)       warnx(__VA_ARGS__)
#define VLOGX(...)      vwarnx(__VA_ARGS__)

#define ERR(...)        err(1, __VA_ARGS__)
#define ERRX(...)       errx(1, __VA_ARGS__)
#define VERRX(...)      verrx(1, __VA_ARGS__)

#define LOGSSL(format, ...) LOGX(format ": %s", ##__VA_ARGS__, ERR_error_string(ERR_get_error(), NULL))
#define ERRSSL(format, ...) ERRX(format ": %s", ##__VA_ARGS__, ERR_error_string(ERR_get_error(), NULL))

#if 0
static inline void
LOGBLOB(const char* label, uint8_t* blob, size_t len)
{
    printf("%s (%zd):", label, len);
    while (len-- > 0)
        printf(" %02x", *blob++);

    printf("\n");
}
#else
#define LOGBLOB(...)
#endif
