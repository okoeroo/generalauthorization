#include "genauthz_common.h"
#include <sha256.h>


char * htp_method_to_string(htp_method method) {
    switch (method) {
        case htp_method_GET       : return "GET";
        case htp_method_HEAD      : return "HEAD";
        case htp_method_POST      : return "POST";
        case htp_method_PUT       : return "PUT";
        case htp_method_DELETE    : return "DELETE";
        case htp_method_MKCOL     : return "MKCOL";
        case htp_method_COPY      : return "COPY";
        case htp_method_MOVE      : return "MOVE";
        case htp_method_OPTIONS   : return "OPTIONS";
        case htp_method_PROPFIND  : return "PROPFIND";
        case htp_method_PROPPATCH : return "PROPPATCH";
        case htp_method_LOCK      : return "LOCK";
        case htp_method_UNLOCK    : return "UNLOCK";
        case htp_method_TRACE     : return "TRACE";
        case htp_method_UNKNOWN   : return "UNKNOWN";
        default                   : return "UNKNOWN";
    }
}


static const char *job_output_dir = NULL;

const char *
get_job_output_dir(void) {
    return job_output_dir;
}

void
set_job_output_dir(const char *path) {
    job_output_dir = path;
}

int
create_job_output_directory(const char * path) {
    if (path == NULL) {
        return -1;
    }

    if (mkdir(path, 00755) < 0) {
        if (errno == EEXIST) {
            printf("The output directory \"%s\" already exists\n", path);
            return 0;
        }
        syslog(LOG_ERR, "Error: could not created Output of jobs will be collected in: \"%s\", error msg: %s\n",
                        path,
                        strerror(errno));
        return -1;
    }
    syslog(LOG_NOTICE, "Output of jobs will be collected in: \"%s\"\n", path);
    printf("Output of jobs will be collected in: \"%s\"\n", path);
    return 0;
}

char *
genauthz_common_get_ip_addr_far_side(evhtp_request_t * req) {
    char *ip_addr_far_side;

    if (!(req && req ->conn && req ->conn->saddr)) {
        return NULL;
    }

    ip_addr_far_side = malloc(INET6_ADDRSTRLEN);
    if (ip_addr_far_side == NULL) {
        syslog(LOG_ERR, "Could not allocate %d bytes of memory.\n", INET6_ADDRSTRLEN);
        return NULL;
    }

    switch (req->conn->saddr->sa_family) {
        case AF_INET:
            if (inet_ntop(req->conn->saddr->sa_family,
                          &(((struct sockaddr_in*)req->conn->saddr)->sin_addr),
                          ip_addr_far_side, INET6_ADDRSTRLEN) == NULL) {
                goto cleanup;
            }
            break;
        case AF_INET6:
            if (inet_ntop(req->conn->saddr->sa_family,
                          &(((struct sockaddr_in6*)req->conn->saddr)->sin6_addr),
                          ip_addr_far_side, INET6_ADDRSTRLEN) == NULL) {
                goto cleanup;
            }
            break;
        default:
            syslog(LOG_ERR, "Address family not supported\n");
            goto cleanup;
    }

    /* Needs free */
    return ip_addr_far_side;

cleanup:
    free(ip_addr_far_side);
    return NULL;
}


struct evbuffer *
genauthz_ev_sha256(struct evbuffer *input) {
    struct evbuffer *output = NULL;
    sha256_context *sha256_ctx = NULL;
    unsigned char *sha256 = NULL;

    /* Allocate some mem */
    if ((sha256 = malloc(32)) == NULL) {
        goto cleanup;
    }
    if ((sha256_ctx = malloc(sizeof(sha256_context))) == NULL) {
        goto cleanup;
    }
    if ((output = evbuffer_new()) == NULL) {
        goto cleanup;
    }

    /* Hash the secret */
    sha256_starts(sha256_ctx);
    sha256_update(sha256_ctx,
                  (uint8 *) evbuffer_pullup(input, evbuffer_get_length(input)),
                  evbuffer_get_length(input));
    sha256_finish(sha256_ctx, sha256);

    /* Format the sha256 output into the buffer */
    evbuffer_add_printf(
        output,
        "%02x%02x%02x%02x%02x%02x%02x%02x" \
        "%02x%02x%02x%02x%02x%02x%02x%02x" \
        "%02x%02x%02x%02x%02x%02x%02x%02x" \
        "%02x%02x%02x%02x%02x%02x%02x%02x",
        sha256[0],  sha256[1],  sha256[2],  sha256[3],  sha256[4],  sha256[5],  sha256[6],  sha256[7],
        sha256[8],  sha256[9],  sha256[10], sha256[11], sha256[12], sha256[13], sha256[14], sha256[15],
        sha256[16], sha256[17], sha256[18], sha256[19], sha256[20], sha256[21], sha256[22], sha256[23],
        sha256[24], sha256[25], sha256[26], sha256[27], sha256[28], sha256[29], sha256[30], sha256[31]);

    /* liberate memory */
    if (sha256) { free(sha256); }
    if (sha256_ctx) { free(sha256_ctx); }
    return output;

cleanup:
    /* liberate memory - failure */
    if (output) { evbuffer_free(output); }
    if (sha256) { free(sha256); }
    if (sha256_ctx) { free(sha256_ctx); }
    return NULL;
}

int
genauthz_write_evbuffer_to_disk(struct evbuffer *buf, const char *path, int oflag, int perms) {
    int fd = 0;
    size_t num = 0, n = 0;
    unsigned char *data = NULL;

    if (buf == NULL || path == NULL)
        return -1;

    errno = 0;

    fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IXUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
        printf("%s: Error: writing to \"%s\" failed: %s\n", __func__, path, strerror(errno));
        return -1;
    }

    num = evbuffer_get_length(buf);
    if (num == 0)
        return -1;

    data = malloc(num);
    if (data == NULL) {
        printf("%s: Error: could not allocate %ld bytes: %s\n", __func__, num, strerror(errno));
        return -1;
    }

    evbuffer_copyout(buf, data, num);
    n = write(fd, data, num);
    if (n != num) {
        printf("%s: Warning: written %ld bytes out of the expected %ld: %s\n", __func__, n, num, strerror(errno));
    }

    close(fd);
    free(data);
    return n;
}

