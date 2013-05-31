#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include <string.h>
#include <strings.h>

#include "queue.h"
#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_xacml_rule_parser.h"
#include "genauthz_callout_helper.h"


#ifndef GENAUTHZ_EVALUATOR_H
    #define GENAUTHZ_EVALUATOR_H

evhtp_res
pdp_policy_evaluation(request_mngr_t *request_mngr);

#endif /* GENAUTHZ_EVALUATOR_H */
