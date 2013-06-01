#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>

#include <evhtp.h>
#include <libxml/parser.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


#ifndef GA_MAIN_H
    #define GA_MAIN_H

#include "genauthz/generalauthorization.h"
#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_conf.h"
#include "genauthz/genauthz_callout_helper.h"
#include "genauthz/genauthz_xacml_rule_parser.h"


#define CNC_CERT_FILE "/etc/generalauthorization/cert.pem"
#define CNC_PRIV_FILE "/etc/generalauthorization/cert.key"


struct event_base *get_event_base(void);
void set_event_base(struct event_base *base);

#endif /* GA_MAIN_H */
