#ifndef GA_HTTPREST_H
    #define GA_HTTPREST_H

#include <stdio.h>
#include <evhtp.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <unistd.h>

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_pap.h"
#include "genauthz/genauthz_pdp.h"
#include "genauthz/genauthz_control.h"
#include "genauthz/genauthz_normalized_xacml.h"


#define GA_HTTP_IP_ADDRESS_LEN               64
#define GA_HTTP_HEADER_CONTENT_TYPE "Content-Type"
#define GA_HTTP_HEADER_CONTENT_TYPE_XACML_XML_V3 "application/xacml+xml; version=3.0"
#define GA_HTTP_HEADER_CONTENT_TYPE_XACML_JSON_V3 "application/xacml+json; version=3.0"


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
    short verbose;
    short foreground;
    const char *conf_file;
    evhtp_t  * evhtp;
    evbase_t * evbase;
    tq_listener_list_t listener_head;
    struct xacml_policy_s *xacml_policy;

    /* Total call count */
    uint64_t   total_call_count;
    uint32_t   threads_online;
};

struct app {
    struct app_parent *parent;
    evbase_t          *evbase;
    evhtp_t           *evhtp;

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

/*! Multi-family socket end-point address. */
typedef union mf_sock_address {
    struct sockaddr         *sa;
    struct sockaddr_in      *sa_in;
    struct sockaddr_in6     *sa_in6;
    struct sockaddr_storage *sa_stor;
} mf_sock_address_t;

struct request_mngr_s {
    evhtp_request_t            *evhtp_req;
    evhtp_connection_t         *conn;
    mf_sock_address_t          *mf_sock;
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
    int                         paused;
};

/* functions */
evthr_t *get_request_thr(evhtp_request_t *);
struct request_mngr_s *create_request_mngr_from_evhtp_request_with_arg(
            evhtp_request_t       *req,
            void                  *arg,
            const char            *context);
void delete_request_mngr(struct request_mngr_s *);
const char *mimetype_normalizer_str(int);
int mimetype_normalizer_int(evhtp_request_t *, const char *);

int genauthz_httprest_init(evbase_t *, struct app_parent *);


#endif /* GA_HTTPREST_H */

