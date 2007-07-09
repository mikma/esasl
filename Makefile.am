SUBDIRS = src c_src

AM_ERL_FLAGS = -pa ../esasl/ebin -pa ~/tmp/cvs/jungerl/lib/eldap/ebin

check:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -noshell -name esasl -run esasl test -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
