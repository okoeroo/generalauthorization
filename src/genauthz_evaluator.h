#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>

#include "queue.h"
#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"


#ifndef GENAUTHZ_EVALUATOR_H
    #define GENAUTHZ_EVALUATOR_H

evhtp_res
pdp_policy_evaluation(struct tq_xacml_request_s *xacml_req,
                      struct tq_xacml_response_s *xacml_res,
                      struct xacml_policy_s *xacml_policy);

#endif /* GENAUTHZ_EVALUATOR_H */
