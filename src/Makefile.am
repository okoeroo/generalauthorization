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


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgenauthz_core.pc

genauthzincludedir = $(includedir)/genauthz

lib_LTLIBRARIES = libgenauthz_core.la

core_headers = \
        $(srcdir)/generalauthorization.h \
        $(srcdir)/tree.h \
        $(srcdir)/queue.h \
        $(srcdir)/sha256.h \
        $(srcdir)/genauthz_common.h \
        $(srcdir)/genauthz_conf.h \
        $(srcdir)/genauthz_xacml_rule_parser.h \
        $(srcdir)/genauthz_callout_helper.h \
        $(srcdir)/genauthz_xacml.h \
        $(srcdir)/genauthz_normalized_xacml.h \
        $(srcdir)/genauthz_xml_xacml.h \
        $(srcdir)/genauthz_json_xacml.h \
        $(srcdir)/genauthz_evaluator.h \
        $(srcdir)/genauthz_pap.h \
        $(srcdir)/genauthz_pdp.h \
        $(srcdir)/genauthz_control.h \
        $(srcdir)/genauthz_httprest.h

libgenauthz_core_la_SOURCES = \
        $(core_headers) \
        $(srcdir)/sha256.c \
        $(srcdir)/genauthz_common.c \
        $(srcdir)/genauthz_conf.c \
        $(srcdir)/genauthz_xacml_rule_parser.c \
        $(srcdir)/genauthz_callout_helper.c \
        $(srcdir)/genauthz_xacml.c \
        $(srcdir)/genauthz_normalized_xacml.c \
        $(srcdir)/genauthz_xml_xacml.c \
        $(srcdir)/genauthz_json_xacml.c \
        $(srcdir)/genauthz_evaluator.c \
        $(srcdir)/genauthz_pap.c \
        $(srcdir)/genauthz_pdp.c \
        $(srcdir)/genauthz_control.c \
        $(srcdir)/genauthz_httprest.c

libgenauthz_core_includedir = $(includedir)/genauthz/
libgenauthz_core_ladir = $(includedir)/genauthz/
nobase_libgenauthz_core_la_HEADERS = \
        $(core_headers) \
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

