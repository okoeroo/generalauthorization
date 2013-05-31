
AM_CPPFLAGS = \
	-I$(srcdir)/../src/ \
	-I$(srcdir) \
	$(ADD_THESE_DEFINES)


libgenauthz_example_la_LDFLAGS = -avoid-version -lgenauthz_core
libgenauthz_example_la_LDFLAGS += -L../src/.libs/

lib_LTLIBRARIES = libgenauthz_example.la

libgenauthz_example_la_SOURCES = \
	example_main.h \
	example_main.c

