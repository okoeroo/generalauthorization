#ifndef GENAUTHZ_EVALUATOR_H
    #define GENAUTHZ_EVALUATOR_H

#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>
#include <strings.h>

#include "genauthz/queue.h"
#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_httprest.h"
#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_normalized_xacml.h"
#include "genauthz/genauthz_xacml_rule_parser.h"
#include "genauthz/genauthz_callout_helper.h"


evhtp_res
pdp_policy_evaluation(request_mngr_t *request_mngr);

#endif /* GENAUTHZ_EVALUATOR_H */
