#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>

#include <confuse.h>

#include "genauthz_common.h"
#include "genauthz_xacml.h"


#ifndef GENAUTHZ_XACML_RULE_PARSER_H
    #define GENAUTHZ_XACML_RULE_PARSER_H

void
print_loaded_policy(struct xacml_policy_s *xacml_policy);
int
rule_parser(char *policy_file,
            struct xacml_policy_s **xacml_policy);

#endif /* GENAUTHZ_XACML_RULE_PARSER_H */
