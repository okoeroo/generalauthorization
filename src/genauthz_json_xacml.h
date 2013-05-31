#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>
#include <jansson.h>


#ifndef GENAUTHZ_JSON_XACML_H
    #define GENAUTHZ_JSON_XACML_H

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"


evhtp_res
pdp_json_input_processor(struct tq_xacml_request_s **xacml_req,
                        evhtp_request_t *evhtp_req);
evhtp_res pdp_json_output_processor(struct evbuffer *output,
                                   struct tq_xacml_response_s *xacml_res);

#endif
