#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"

#include <string.h>
#include <libxml/tree.h>
#include <libxml/parser.h>


#ifndef GENAUTHZ_XML_XACML_H
    #define GENAUTHZ_XML_XACML_H

void walk(xmlNodePtr node, int depth);
void walk_ns(xmlNs *ns);
void walk_properties(struct _xmlAttr *xa);

evhtp_res pdp_xml_input_processor(struct tq_xacml_request_s **xacml_req,
                                  evhtp_request_t *evhtp_req);
evhtp_res pdp_xml_output_processor(struct evbuffer *output,
                                   struct tq_xacml_response_s *xacml_res);

#endif
