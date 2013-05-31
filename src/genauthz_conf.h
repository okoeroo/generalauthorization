#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>

#include "confuse.h"


#ifndef GENAUTHZ_CONF_H
    #define GENAUTHZ_CONF_H

#include "generalauthorization.h"

#include "genauthz_main.h"
#include "genauthz_common.h"
#include "genauthz_httprest.h"


int
configuration(struct app_parent *app_p,
              const char *configfile,
              char **policy_file,
              char **syslog_ident,
              int *syslog_flags,
              int *syslog_facility);


#endif /* GENAUTHZ_CONF_H */
