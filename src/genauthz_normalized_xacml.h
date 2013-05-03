#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"


#ifndef GENAUTHZ_NORMALIZED_XACML_H
    #define GENAUTHZ_NORMALIZED_XACML_H

const char *xacml_category_type2str(enum ga_xacml_category_e type);
const char *xacml_decision2str(enum ga_xacml_decision_e desc);
void print_normalized_xacml_response(struct tq_xacml_response_s *response);
void print_normalized_xacml_request(struct tq_xacml_request_s *request);
void delete_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *value);
void delete_normalized_xacml_attribute(struct tq_xacml_attribute_s *attribute);
void delete_normalized_xacml_category(struct tq_xacml_category_s *category);
void delete_normalized_xacml_response(struct tq_xacml_response_s *response);
void delete_normalized_xacml_request(struct tq_xacml_request_s *request);

struct tq_xacml_response_s *create_normalized_xacml_response(void);
struct tq_xacml_attribute_value_s *create_normalized_xacml_attribute_value(void);
struct tq_xacml_attribute_s *create_normalized_xacml_attribute(void);
struct tq_xacml_category_s *create_normalized_xacml_category(void);

struct tq_xacml_attribute_value_s *deep_copy_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *original);
struct tq_xacml_attribute_s *deep_copy_normalized_xacml_attribute(struct tq_xacml_attribute_s *original);
struct tq_xacml_category_s *deep_copy_normalized_xacml_category(struct tq_xacml_category_s *original);

evhtp_res pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                                struct tq_xacml_response_s *xacml_res,
                                struct xacml_policy_s *xacml_policy);

#endif /* GENAUTHZ_NORMALIZED_XACML_H */
