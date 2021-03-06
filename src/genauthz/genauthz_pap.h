#ifndef GENAUTHZ_PAP_H
    #define GENAUTHZ_PAP_H

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <evhtp.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <pwd.h>

#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_normalized_xacml.h"
#include "genauthz/genauthz_xacml_rule_parser.h"
#include "genauthz/genauthz_evaluator.h"


void pap_cb(evhtp_request_t *req, void *a);


#endif
