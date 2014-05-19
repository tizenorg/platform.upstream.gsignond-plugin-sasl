extensionsdir = $(EXTENSIONSDIR)
pluginsdir = $(PLUGINSDIR)

plugins_LTLIBRARIES = libsasl.la
NULL=

libsasl_la_CPPFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(NULL)

libsasl_la_LIBADD = \
    $(GSIGNON_LIBS) \
    $(NULL)

libsasl_la_SOURCES = \
    gsignond-sasl-plugin.c \
    gsignond-sasl-plugin.h \
    $(NULL)

libsasl_la_LDFLAGS = -avoid-version

CLEANFILES = 
