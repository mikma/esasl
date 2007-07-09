SUBDIRS = esasl

AM_ERL_FLAGS = -pa esasl/ebin

check:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -noshell -name esasl -run esasl test -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
