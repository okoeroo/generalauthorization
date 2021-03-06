#ifndef GENAUTHZ_XML_XACML_H
    #define GENAUTHZ_XML_XACML_H

#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>

#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_pdp.h"
#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_normalized_xacml.h"


evhtp_res pdp_xml_input_processor(struct tq_xacml_request_s **xacml_req,
                                  evhtp_request_t *evhtp_req);

int normalized_xacml_attribute_values2xml_evbuffer(struct evbuffer *output,
                                                   tq_xacml_attribute_value_list_t attr_value_list);
int normalized_xacml_attributes2xml_evbuffer(struct evbuffer *output,
                                             tq_xacml_attribute_list_t attr_list);
int normalized_xacml_categories2xml_evbuffer(struct evbuffer *output,
                                             tq_xacml_category_list_t cat_list);
evhtp_res pdp_xml_output_processor(struct evbuffer *output,
                                   struct tq_xacml_response_s *xacml_res);

#endif
