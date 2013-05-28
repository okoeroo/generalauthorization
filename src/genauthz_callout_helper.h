#include <dlfcn.h>
#include "genauthz_normalized_xacml.h"


#ifndef GENAUTHZ_CALLOUT_HELPER_H
    #define GENAUTHZ_CALLOUT_HELPER_H

int genauthz_initialize_rule_callbacks(struct xacml_policy_s *xacml_policy);

#endif
