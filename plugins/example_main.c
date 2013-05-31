#include "example_main.h"


int
example_plugin_init(int argc, char **argv) {
    int i;

    for (i = 0; i < argc; i++) {
        printf("Argv[%d]: %s\n", i, argv[i]);
    }

    return 0;
}

void
example_plugin_uninit(void) {
    return;
}

void
example_plugin_rule_hit(request_mngr_t *request_mngr, tq_xacml_rule_t rule) {



    return;
}


