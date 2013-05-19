#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_xacml.h"

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
#define IP_ADDRESS_LEN               64


typedef enum {
    TYPE_APP_UNKNOWN,
    TYPE_APP_ALL,
    TYPE_APP_XML,
    TYPE_APP_JSON,
    TYPE_APP_XACML_XML,
    TYPE_APP_XACML_JSON
} ga_app_accept_t;

struct tq_service_s {
    struct tq_listener_s *parent_listener;
    service_type_t        ltype;
    char                 *uri;

    /* URI specific call count */
    uint64_t        uri_call_count;
    short           thread_cnt;

    TAILQ_ENTRY(tq_service_s) next;
};

typedef struct tq_listener_list_s tq_listener_list_t;
TAILQ_HEAD(tq_listener_list_s, tq_listener_s);

struct app_parent {
    short debug;
    evhtp_t  * evhtp;
    evbase_t * evbase;
    tq_listener_list_t listener_head;
    struct xacml_policy_s *xacml_policy;

    /* Total call count */
    uint64_t   total_call_count;
    uint32_t   threads_online;
};

struct app {
    struct app_parent * parent;
    evbase_t          * evbase;

    /* Thread specific call count */
    uint64_t            thread_call_count;
    uint32_t            thread_number;
};

struct tq_listener_s {
    char   *bindip;
    short   port;
    short   backlog;
    char   *cert;
    char   *key;
    char   *cafile;
    char   *capath;
    char   *crlpath;
    char   *cert_password;
    char   *cipherlist;
    short   clientauth;
    short   rfc3820;
    char   *whitelist_path;
    char   *blacklist_path;

    evhtp_t           *evhtp;
    evhtp_ssl_cfg_t   *scfg;
    struct app        *app_thr;
    struct app_parent *app_parent;

    /* Listener specific call count */
    uint64_t            listener_call_count;

    TAILQ_HEAD(, tq_service_s) services_head;
    TAILQ_ENTRY(tq_listener_s) next;
};

struct request_mngr_s {
    evhtp_request_t            *evhtp_req;
    evhtp_connection_t         *conn;
    struct sockaddr_in         *sin;
    char                       *sin_ip_addr;
    uint16_t                    sin_port;
    evthr_t                    *evhtp_thr;
    struct tq_listener_s       *listener;
    struct tq_service_s        *service;
    struct app                 *app;
    pthread_t                   pthr;
    uint64_t                    pid;
    int                         accept_type;
    int                         content_type;
    const char                 *accept_header;
    const char                 *contenttype_header;
    struct tq_xacml_request_s  *xacml_req;
    struct tq_xacml_response_s *xacml_res;
};

/* functions */
evthr_t *get_request_thr(evhtp_request_t *);
void delete_request_mngr(struct request_mngr_s *);
const char *mimetype_normalizer_str(int);
int mimetype_normalizer_int(evhtp_request_t *, const char *);

int genauthz_httprest_init(evbase_t *, struct app_parent *);


#endif /* GA_HTTPREST_H */

