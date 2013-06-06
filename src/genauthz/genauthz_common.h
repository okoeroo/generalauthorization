#ifndef GA_COMMON_H
    #define GA_COMMON_H

#ifndef _LARGEFILE64_SOURCE
    #define _LARGEFILE64_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/stat.h>
#include <evhtp.h>

#include <fcntl.h>

#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/param.h>


#define GA_GOOD (int)0
#define GA_BAD (int)1

#ifdef HAVE_LSEEK
    #define LSEEK lseek64
    #define OFF_T off64_t
#else
    #define LSEEK lseek
    #define OFF_T off_t
#endif


#define evpull(x) \
    evbuffer_pullup(x, evbuffer_get_length(x))

#define malloc_or_cleanup(x,y) \
    x = malloc(y); \
    if (x == NULL) { \
        goto cleanup; \
    }

#define strdup_or_cleanup(x,y) \
    x = strdup(y); \
    if (x == NULL) { \
        goto cleanup; \
    }

/* From libevhtp's evhtp.c */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)        \
    for ((var) = TAILQ_FIRST((head));                     \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

#ifndef TAILQ_COUNT
#define TAILQ_COUNT(counter, val, head, tvar) \
    TAILQ_FOREACH(val, head, tvar) { \
        counter++; \
    }
#endif

#ifndef TAILQ_COUNT_SAFE
#define TAILQ_COUNT_SAFE(counter, val, head, tvar) \
    counter = 0; \
    TAILQ_FOREACH(val, head, tvar) { \
        counter++; \
    }
#endif

typedef enum answer_e {
    NO = 0,
    YES,
    OPTIONAL,
    MAYBE
} answer_t;

typedef enum service_type_e {
    NONE,
    CONTROL,
    PAP,
    PDP,
    PEP
} service_type_t;

const char *
get_job_output_dir(void);

void
set_job_output_dir(const char *path);

int
create_job_output_directory(const char * path);

const char *
htp_method_to_string(htp_method method);

char *
genauthz_common_get_ip_addr_far_side(evhtp_request_t * req);

struct evbuffer *
genauthz_ev_sha256(struct evbuffer *input);

int
genauthz_write_evbuffer_to_disk(struct evbuffer *buf, const char *path, int oflag, int perms);

#endif
