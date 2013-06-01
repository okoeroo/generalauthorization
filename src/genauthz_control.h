#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <evhtp.h>
#include <sys/types.h>
#include <pwd.h>
#include <inttypes.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#ifndef GENAUTHZ_CONTROL_H
    #define GENAUTHZ_CONTROL_H

#include "genauthz/generalauthorization.h"

#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_normalized_xacml.h"
#include "genauthz/genauthz_xacml_rule_parser.h"


void control_cb(evhtp_request_t *req, void *a);

#endif

