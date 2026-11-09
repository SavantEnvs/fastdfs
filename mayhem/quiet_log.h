/* libfastcommon's logger must be initialised before the client code logs. Keep it live (so log
 * formatting of fuzz-controlled strings stays covered) but send the output to /dev/null. */
#ifndef MAYHEM_QUIET_LOG_H
#define MAYHEM_QUIET_LOG_H

#include <fcntl.h>
#include <stdlib.h>
#include "fastcommon/logger.h"

static inline void mayhem_quiet_log_init(void)
{
    if (log_init() != 0) {
        abort();
    }
    g_log_context.log_fd = open("/dev/null", O_WRONLY);
}

#endif
