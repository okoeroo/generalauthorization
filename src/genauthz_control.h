#include <sys/types.h>
#include <pwd.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <syslog.h>
#include <stdio.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"


#ifndef GENAUTHZ_CONTROL_H
    #define GENAUTHZ_CONTROL_H

void control_cb(evhtp_request_t *req, void *a);

#endif

