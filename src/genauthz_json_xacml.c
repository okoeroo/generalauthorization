#include <stdio.h>
#include <syslog.h>
#include <evhtp.h>

#include "genauthz_common.h"
#include "genauthz_httprest.h"
#include "genauthz_pdp.h"
#include "genauthz_xacml.h"
#include "genauthz_normalized_xacml.h"
#include "genauthz_json_xacml.h"

#include <string.h>


evhtp_res
pdp_json_output_processor(struct evbuffer *output,
                         struct tq_xacml_response_s *xacml_res) {
    evhtp_res http_res = EVHTP_RES_200;

    /* Response header */
    evbuffer_add_printf(output,
            "{\n"
            "    \"Response\" : {\n"
            "        \"Result\" : {\n"
            "            \"Decision\" : \"%s\"\n"
            "        }\n"
            "    }\n"
            "}\n",
            xacml_decision2str(xacml_res->decision));

#if 0
    /* Obligations */
    if (!(TAILQ_EMPTY(&(xacml_res->obligations)))) {
        evbuffer_add_printf(output, "    <Obligations>\n");
        normalized_xacml_categories2xml_evbuffer(output, xacml_res->obligations);
        evbuffer_add_printf(output, "    </Obligations>\n");
    }
    /* Associated Advice */
    if (!(TAILQ_EMPTY(&(xacml_res->advices)))) {
        evbuffer_add_printf(output, "    <AssociatedAdvice>\n");
        normalized_xacml_categories2xml_evbuffer(output, xacml_res->advices);
        evbuffer_add_printf(output, "    </AssociatedAdvice>\n");
    }
    /* IncludeInResult Attributes */
    if (!(TAILQ_EMPTY(&(xacml_res->attributes)))) {
        evbuffer_add_printf(output, "    <Attributes>\n");
        normalized_xacml_attributes2xml_evbuffer(output, xacml_res->attributes);
        evbuffer_add_printf(output, "    </Attributes>\n");
    }

    /* Finalize */
    evbuffer_add_printf(output,
            "  </Result>\n");
    evbuffer_add_printf(output,
            "</Response>\n");
#endif

    return http_res;
}
