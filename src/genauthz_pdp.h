#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/types.h>
#include <pwd.h>
#include <evhtp.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#ifndef GENAUTHZ_PDP_H
    #define GENAUTHZ_PDP_H

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"
#include "genauthz_evaluator.h"
#include "genauthz_xml_xacml.h"
#include "genauthz_json_xacml.h"


void pdp_cb(evhtp_request_t *req, void *a);


#endif
