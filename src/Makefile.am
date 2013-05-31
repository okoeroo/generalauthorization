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


lib_LTLIBRARIES = libgenauthz_core.la

libgenauthz_core_la_SOURCES = \
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
        genauthz_httprest.c

libgenauthz_core_ladir = $(includedir)/genauthz/
nobase_libgenauthz_core_la_HEADERS = \
        $(srcdir)/genauthz_common.h \
        $(srcdir)/genauthz_xacml.h \
        $(srcdir)/genauthz_normalized_xacml.h \
        $(srcdir)/genauthz_xacml_rule_parser.h \
        $(srcdir)/genauthz_callout_helper.h \
        $(srcdir)/genauthz_plugin.h

libgenauthz_core_la_CPPFLAGS = -I/usr/include/libxml2
libgenauthz_core_la_LDFLAGS = -fstack-protector -avoid-version


bin_PROGRAMS = generalauthorizationd

generalauthorizationd_SOURCES = \
        generalauthorization.h \
        genauthz_main.h \
        main.c

generalauthorizationd_CPPFLAGS = -I/usr/include/libxml2
generalauthorizationd_LDFLAGS = -fstack-protector -lgenauthz_core

