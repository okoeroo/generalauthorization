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

int
rule_parser(char *policy_file,
            tq_xacml_rule_list_t xacml_policy_rule_list);

#endif /* GENAUTHZ_XACML_RULE_PARSER_H */
