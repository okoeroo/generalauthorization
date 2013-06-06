#ifndef GENAUTHZ_CONF_H
    #define GENAUTHZ_CONF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>

#include "confuse.h"

#include "genauthz/genauthz_main.h"
#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"


#define STRDUP_OR_GOTO_CLEANUP(dst,src) do { \
    if (src) {                               \
        dst = strdup(src);                   \
        if (dst == NULL)                     \
            goto cleanup;                    \
    }                                        \
} while(0)


int
configuration(struct app_parent *app_p,
              const char *configfile,
              char **policy_file,
              char **syslog_ident,
              int *syslog_flags,
              int *syslog_facility);


#endif /* GENAUTHZ_CONF_H */
