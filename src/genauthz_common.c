#include "ga_config.h"
#include "genauthz/genauthz_common.h"


const char *
htp_method_to_string(htp_method method) {
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

