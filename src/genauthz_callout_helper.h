#include <dlfcn.h>
#include "genauthz_normalized_xacml.h"


#ifndef GENAUTHZ_CALLOUT_HELPER_H
    #define GENAUTHZ_CALLOUT_HELPER_H

int genauthz_initialize_rule_callbacks(struct xacml_policy_s *xacml_policy);
int genauthz_execute_rule_callouts(request_mngr_t *request_mngr,
                                   struct tq_xacml_rule_s *rule);

/* Plug-in helper function */
int    genauthz_callout_get_argc(struct tq_xacml_callout_s *callout);
char **genauthz_callout_get_argv(struct tq_xacml_callout_s *callout);
void  *genauthz_callout_get_aux (struct tq_xacml_callout_s *callout);
void   genauthz_callout_set_aux (struct tq_xacml_callout_s *callout, void *);

#endif
