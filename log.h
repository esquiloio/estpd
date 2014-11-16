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
