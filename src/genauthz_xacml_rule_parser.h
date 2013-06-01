#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <signal.h>

#include <confuse.h>


#ifndef GENAUTHZ_XACML_RULE_PARSER_H
    #define GENAUTHZ_XACML_RULE_PARSER_H

#include "genauthz/genauthz_common.h"
#include "genauthz/genauthz_xacml.h"
#include "genauthz/genauthz_normalized_xacml.h"


void policy_2_evb(struct evbuffer *, struct xacml_policy_s *);
void print_loaded_policy(struct xacml_policy_s *);
int rule_parser(char *, struct xacml_policy_s **);

#endif /* GENAUTHZ_XACML_RULE_PARSER_H */
