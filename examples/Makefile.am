noinst_PROGRAMS = gsignond-sasl-example

gsignond_sasl_example_SOURCES = gsignond-sasl-example.c
gsignond_sasl_example_CFLAGS = \
    $(GSIGNON_CFLAGS) \
    -I$(top_srcdir)/src/

gsignond_sasl_example_LDADD = \
    $(top_builddir)/src/libsasl.la \
    $(GSIGNON_LIBS)

all-local: $(top_builddir)/docs/gsignond-sasl-example.listing

mostlyclean-local: 
	rm -rf $(top_builddir)/docs/gsignond-sasl-example.listing

$(top_builddir)/docs/gsignond-sasl-example.listing:
	cp $(top_srcdir)/examples/gsignond-sasl-example.c $(top_builddir)/docs/gsignond-sasl-example.listing
