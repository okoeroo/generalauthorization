#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>
#include <string.h>

#include "queue.h"


#ifndef GENAUTHZ_NORMALIZED_XACML_H
    #define GENAUTHZ_NORMALIZED_XACML_H

#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_pdp.h"
#include "genauthz/genauthz_xacml.h"


const char *xacml_category_type2str(enum ga_xacml_category_e type);
const char *xacml_decision2str(enum ga_xacml_decision_e desc);
void print_normalized_xacml_response(struct tq_xacml_response_s *response);
void print_normalized_xacml_request(struct tq_xacml_request_s *request);
void delete_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *value);
void delete_normalized_xacml_attribute(struct tq_xacml_attribute_s *attribute);
void delete_normalized_xacml_category(struct tq_xacml_category_s *category);
void delete_normalized_xacml_response(struct tq_xacml_response_s *response);
void delete_normalized_xacml_request(struct tq_xacml_request_s *request);

struct tq_xacml_request_s  *create_normalized_xacml_request(void);
struct tq_xacml_response_s *create_normalized_xacml_response(void);
struct tq_xacml_attribute_value_s *create_normalized_xacml_attribute_value(void);
struct tq_xacml_attribute_s *create_normalized_xacml_attribute(void);
struct tq_xacml_category_s *create_normalized_xacml_category(void);

struct tq_xacml_attribute_value_s *deep_copy_normalized_xacml_attribute_value(struct tq_xacml_attribute_value_s *original);
struct tq_xacml_attribute_s *deep_copy_normalized_xacml_attribute(struct tq_xacml_attribute_s *original);
struct tq_xacml_category_s *deep_copy_normalized_xacml_category(struct tq_xacml_category_s *original);

#endif /* GENAUTHZ_NORMALIZED_XACML_H */
