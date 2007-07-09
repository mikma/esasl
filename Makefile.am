SUBDIRS = src c_src

AM_ERL_FLAGS = -pa ../esasl/ebin -pa ~/tmp/cvs/jungerl/lib/eldap/ebin

all-local:
	test -e ebin || ln -s src ebin
	test -e priv || ln -s c_src priv

clean-local:
	-test -L ebin && $(RM) ebin
	-test -L priv && $(RM) priv

check:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -noshell -name esasl -run esasl test -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
