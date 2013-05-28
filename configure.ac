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
#    Oscar Koeroo <okoeroo@nikhef.nl>
#
######################################################################

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([General Authorization], [0.0.4], okoeroo@gmail.com)
#AC_CONFIG_MACRO_DIR([autodir])
AM_INIT_AUTOMAKE([1.6.3 subdir-objects foreign])
AC_CONFIG_SRCDIR([src/generalauthorization.h.in])

# Notices.
AC_COPYRIGHT([Copyright (c) 2013 of Oscar Koeroo
See LICENCE file for details
])
AC_REVISION([$Revision: 1.28 $])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

DISTBIN=$WORKDIR/../../dist
AC_SUBST(DISTBIN)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h assert.h confuse.h ctype.h dirent.h dlfcn.h errno.h event2/bufferevent_ssl.h event2/event.h event2/thread.h evhtp.h fcntl.h float.h limits.h malloc.h pthread.h pwd.h queue.h signal.h stdarg.h stdint.h stdio.h stdlib.h string.h syslog.h sys/param.h sys/stat.h sys/time.h sys/types.h time.h tree.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([setenv strchr strcspn strdup strerror strncasecmp strpbrk strspn strstr strtol utime])

# Checks for libraries.
# dlopen library
#AC_CHECK_LIB([dl], [dlopen])

AC_CHECK_LIB([dl], [dlopen],[],
    [AC_MSG_FAILURE([no libdl found])])
AC_CHECK_LIB([crypto], [X509_get_subject_name],[],
    [AC_MSG_FAILURE([no libcrypto found])])
AC_CHECK_LIB([ssl], [SSL_library_init],[],
    [AC_MSG_FAILURE([no libssl found])])
AC_CHECK_LIB([event], [evbuffer_add_printf],[],
    [AC_MSG_FAILURE([no libevent found])])
AC_CHECK_LIB([event_openssl], [bufferevent_openssl_socket_new],[],
    [AC_MSG_FAILURE([no libevent_openssl found])])
AC_CHECK_LIB([evhtp], [evhtp_new],[],
    [AC_MSG_FAILURE([no libevhtp found])],[-lpthread])
AC_CHECK_LIB([confuse], [cfg_init],[],
    [AC_MSG_FAILURE([no libconfuse found])])
AC_CHECK_LIB([xml2], [xmlDocGetRootElement],[],
    [AC_MSG_FAILURE([no libxml2 found])])
AC_CHECK_LIB([jansson], [json_array],[],
    [AC_MSG_FAILURE([no libjansson found])])


AC_SUBST(ADD_THESE_DEFINES)

# Configuration items
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

AC_CONFIG_HEADERS([src/generalauthorization.h])

AC_OUTPUT
