#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#define _GNU_SOURCE
#include "confuse.h"

#include "genauthz_main.h"
#include "genauthz_common.h"

#include "generalauthorization.h"
#include "genauthz_httprest.h"

#ifndef GENAUTHZ_CONF_H
    #define GENAUTHZ_CONF_H

int
configuration(struct app_parent *app_p,
              const char *configfile,
              char **syslog_ident,
              int *syslog_flags,
              int *syslog_facility);


#endif /* GENAUTHZ_CONF_H */
