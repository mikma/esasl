SUBDIRS = esasl

EXTRA_DIST = bootstrap

AM_ERL_FLAGS = -pa esasl/ebin

ACLOCAL_AMFLAGS = -I m4

check:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -noshell -name esasl -run esasl test -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
