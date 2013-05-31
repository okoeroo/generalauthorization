#ifndef EXAMPLE_MAIN_H
    #define EXAMPLE_MAIN_H

#include "genauthz_plugin.h"


int
example_plugin_init(int argc, char **argv);

void
example_plugin_uninit(void);

void
example_plugin_rule_hit(request_mngr_t *, tq_xacml_rule_t);


#endif
