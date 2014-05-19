TESTS = saslplugintest
TESTS_ENVIRONMENT= SSO_PLUGINS_DIR=$(top_builddir)/src/.libs

check_PROGRAMS = saslplugintest
saslplugintest_SOURCES = saslplugintest.c
saslplugintest_CFLAGS = \
    $(GSIGNON_CFLAGS) \
    $(CHECK_CFLAGS) \
    -I$(top_srcdir)/src/

saslplugintest_LDADD = \
    $(top_builddir)/src/libsasl.la \
    $(GSIGNON_LIBS) \
    $(CHECK_LIBS)

#These recipes are nicked from gstreamer and simplified
VALGRIND_TESTS_DISABLE = 
SUPPRESSIONS = valgrind.supp

%.valgrind: %
	@$(TESTS_ENVIRONMENT) \
	CK_FORK=no \
	CK_DEFAULT_TIMEOUT=120 \
	G_SLICE=always-malloc \
	$(LIBTOOL) --mode=execute \
	valgrind -q \
	$(foreach s,$(SUPPRESSIONS),--suppressions=$(s)) \
	--tool=memcheck --leak-check=full --trace-children=yes \
	--leak-resolution=high --num-callers=20 \
	--error-exitcode=1 --gen-suppressions=yes \
	./$* 
        
valgrind: $(TESTS)
	for t in $(filter-out $(VALGRIND_TESTS_DISABLE),$(TESTS)); do   \
		$(MAKE) $$t.valgrind;                                   \
	done;                                                         

EXTRA_DIST = valgrind.supp    