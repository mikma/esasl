SUBDIRS = src c_src

AM_ERL_FLAGS = -pa ../esasl/ebin -pa ~/tmp/cvs/jungerl/lib/eldap/ebin

run:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test4
#	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test2

test-esasl:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -name esasl
# -run esasl test xmpp skinner.hem.za.org /home/mikael/src/erlang/ejabberd/xmpp.keytab -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
