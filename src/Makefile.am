# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# 2013-
#    Oscar Koeroo <okoeroo@gmail.nl>
#


AM_CPPFLAGS = \
        $(ADD_THESE_DEFINES)

sbin_PROGRAMS = generalauthorizationd

generalauthorizationd_SOURCES = \
        generalauthorization.h \
        tree.h \
        queue.h \
        sha256.h \
        sha256.c \
        genauthz_common.h \
        genauthz_common.c \
        genauthz_conf.h \
        genauthz_conf.c \
        genauthz_xacml_rule_parser.h \
        genauthz_xacml_rule_parser.c \
        genauthz_callout_helper.h \
        genauthz_callout_helper.c \
        genauthz_xacml.h \
        genauthz_xacml.c \
        genauthz_normalized_xacml.h \
        genauthz_normalized_xacml.c \
        genauthz_xml_xacml.h \
        genauthz_xml_xacml.c \
        genauthz_json_xacml.h \
        genauthz_json_xacml.c \
        genauthz_evaluator.h \
        genauthz_evaluator.c \
        genauthz_pap.h \
        genauthz_pap.c \
        genauthz_pdp.h \
        genauthz_pdp.c \
        genauthz_control.h \
        genauthz_control.c \
        genauthz_httprest.h \
        genauthz_httprest.c \
        genauthz_main.h \
        main.c

# Purposefully at the bottom because waf configuration tests fail with 
# -Wstrict-prototypes and -Werror
generalauthorizationd_CFLAGS = \
        -Wall -O3 -Werror \
        -std=c99 \
        -Wuninitialized \
        -Wbad-function-cast -Wcast-align \
        -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
        -Wcast-qual -Wchar-subscripts -Winline \
        -Wredundant-decls -Wno-long-long \
        -Wshadow -Wstrict-prototypes \
        -g -ggdb -Wall -Wextra \
        -Winit-self -Wformat-security -Wshadow \
        -pedantic -Wpointer-arith -Wcast-align \
        -Wwrite-strings -Wdeclaration-after-statement \
        -Werror-implicit-function-declaration \
        -Wstrict-prototypes -fPIC -pie \
        -fstack-protector -D_FORTIFY_SOURCE=2
generalauthorizationd_CPPFLAGS = -I/usr/include/libxml2
generalauthorizationd_LDFLAGS = -fPIC -fstack-protector

