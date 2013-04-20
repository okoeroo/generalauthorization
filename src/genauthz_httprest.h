#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include <genauthz_common.h>

#ifndef GA_HTTPREST_H
    #define GA_HTTPREST_H

#define GA_HTTP_URI_BASE             "/cnc"
#define GA_HTTP_URI_REGISTERID       GA_HTTP_URI_BASE"/registerid"
#define GA_HTTP_URI_PING             GA_HTTP_URI_BASE"/ping"
#define GA_HTTP_URI_WORK_GETID       GA_HTTP_URI_BASE"/work/getid"
#define GA_HTTP_URI_WORK             GA_HTTP_URI_BASE"/work"
#define GA_HTTP_URI_CONTROL_STATE    GA_HTTP_URI_BASE"/control/state"
#define GA_HTTP_URI_CONTROL_STATUS   GA_HTTP_URI_BASE"/control/status"
#define GA_HTTP_URI_CONTROL_BOTS     GA_HTTP_URI_BASE"/control/bots"
#define GA_HTTP_URI_CONTROL_WORK     GA_HTTP_URI_BASE"/control/work"
#define GA_HTTP_URI_CONTROL          GA_HTTP_URI_BASE"/control"

#define GA_HTTP_BIND_LOCAL_IPV4    "ipv4:127.0.0.1"
#define GA_HTTP_BIND_LOCAL_IPV6    "ipv6:::1"
#define GA_HTTP_BIND_REMOTE_IPV4   "ipv4:0.0.0.0"
#define GA_HTTP_BIND_REMOTE_IPV6   "ipv6:::"
#define GA_HTTP_BIND_REMOTE_PORT   9005
#define GA_HTTP_BIND_LOCAL_PORT    9002
#define GA_HTTP_BOT_LISTENERS      2048
#define GA_HTTP_CONTROL_LISTENERS   512


typedef enum {
    TYPE_APP_UNKNOWN,
    TYPE_APP_ALL,
    TYPE_APP_XML,
    TYPE_APP_JSON,
    TYPE_APP_XACML_XML,
    TYPE_APP_XACML_JSON
} ga_app_accept_t;

struct tq_service_s {
    service_type_t  ltype;
    char            *uri;

    TAILQ_ENTRY(tq_service_s) entries;
};

struct tq_listener_s {
    char               *bindip;
    short               port;
    evhtp_t            *evhtp;
    evhtp_ssl_cfg_t    *scfg;

    TAILQ_ENTRY(tq_listener_s) entries;
    TAILQ_HEAD(, tq_service_s) services_head;
};

typedef struct tq_listener_list_s tq_listener_list_t;
TAILQ_HEAD(tq_listener_list_s, tq_listener_s);


/* functions */
int accept_format(evhtp_request_t *);
int genauthz_httprest_init(evbase_t *, tq_listener_list_t listener_list);


#endif /* GA_HTTPREST_H */

