%%%-------------------------------------------------------------------
%%% File    : gsasl.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : SASL authentication library
%%%
%%% Created : 23 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------
%%%
%%% Copyright (C) 2007  Mikael Magnusson <mikma@users.sourceforge.net>
%%%
%%% Permission is hereby granted, free of charge, to any person
%%% obtaining a copy of this software and associated documentation
%%% files (the "Software"), to deal in the Software without
%%% restriction, including without limitation the rights to use, copy,
%%% modify, merge, publish, distribute, sublicense, and/or sell copies
%%% of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be
%%% included in all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
%%% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
%%% BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
%%% ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
%%% CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
%%% SOFTWARE.
%%%

%%%
%%% TODO: link gsasl process in server_start/client_start and unlink in stop
%%%

-module(esasl).

%% API
-export([start_link/0,
	 start_link/1,
	 start_link/2,
	 start_link/3,
	 stop/1,
	 server_start/4,
	 client_start/4,
	 finish/1,
	 step/2,
	 property_get/2,
	 str_error/2,
	 property_set/3,
	 mechlist/2]).


%% Internal exports
-export([init/4,
	 test/0,
	 test/1,
	 test_init/3,
	 server_init/3,
	 client_init/3]).

-include_lib("kernel/include/inet.hrl").

-define(APP, esasl).

%%-define(ENABLE_DEBUG, yes).

-ifdef(ENABLE_DEBUG).
-define(INFO, io:format).
-define(DEBUG, io:format).
%% -define(WARNING, io:format).
%% -define(ERROR, io:format).
-else.
-define(INFO, ignore).
-define(DEBUG, ignore).
%% -define(WARNING, ignore).
%% -define(ERROR, ignore).
-endif.

-define(WARNING, io:format).
-define(ERROR, io:format).

%%====================================================================
%% API
%%====================================================================

%%--------------------------------------------------------------------
%% Function: start_link([Server_name], [KeyTab, Ccname])
%%           Server_name = {local, Name}
%%           Name = atom()
%%           KeyTab = string(), path to Kerberos keytab
%%           Ccname = string(), Kerberos credential cache name
%% Descrip.: Start gsasl port driver 
%% Returns : {ok, Pid}
%%           Pid = pid()
%%--------------------------------------------------------------------
start_link() ->
    start_link("", "").
start_link(Server_name) ->
    start_link(Server_name, "", "").
start_link(KeyTab, Ccname) when is_list(KeyTab), is_list(Ccname) ->
    start_link('$anonymous', KeyTab, Ccname).
start_link(Server_name, KeyTab, Ccname) when is_list(KeyTab), is_list(Ccname) ->
    ExtProg = filename:join(code:priv_dir(?APP), "gsasl_drv"),
    {ok, proc_lib:start_link(?MODULE, init,
			     [Server_name, KeyTab, ExtProg, Ccname])}.

%%--------------------------------------------------------------------
%% Function: stop(Server_ref)
%%           Server_ref = Name | pid()
%%           Name = atom(), registered name
%% Descrip.: Stop gsasl port driver
%% Returns : ok
%%           
%%--------------------------------------------------------------------
stop(Server_ref) ->
    Server_ref ! stop,
    ok.

%%--------------------------------------------------------------------
%% Function: server_start(Server_ref, Mech, Service, Host)
%%           Server_ref = Name | pid()
%%           Mech = string(), SASL mechanism
%%           Name = atom(), registered name
%%           Service = string(), SASL service name (ex. "HTTP").
%%           Host = string(), server FQDN 
%% Descrip.: Initiate server SASL authentication instance
%% Returns : {ok, Instance} | {error, no_mem}
%%           Instance = integer(), opaque index referencing the instance
%%--------------------------------------------------------------------
server_start(Server_ref, Mech, Service, Host) when is_list(Mech),
						   is_list(Service),
						   is_list(Host) ->
    Pid = lookup_server(Server_ref),
    case call_port(Pid, {start, {server, Mech, Service, Host}}) of
	{ok, Ref} ->
	    {ok, {Pid, Ref}};
	E ->
	    E
    end.

%%--------------------------------------------------------------------
%% Function: client_start(Server_ref, Mech, Service, Host)
%%           Server_ref = Name | pid()
%%           Mech = string(), SASL mechanism
%%           Name = atom(), registered name
%%           Service = string(), SASL service name (ex. "HTTP").
%%           Host = string(), server FQDN 
%% Descrip.: Initiate client SASL authentication instance
%% Returns : {ok, Instance} | {error, no_mem}
%%           Instance = integer(), opaque index referencing the instance
%%--------------------------------------------------------------------
client_start(Server_ref, Mech, Service, Host) when is_list(Mech),
						   is_list(Service),
						   is_list(Host) ->
    Pid = lookup_server(Server_ref),
    case call_port(Pid, {start, {client, Mech, Service, Host}}) of
	{ok, Ref} ->
	    {ok, {Pid, Ref}};
	E ->
	    E
    end.

%%--------------------------------------------------------------------
%% Function: step(Instance, Input)
%%           Instance = integer(), SASL instance
%%           Input = binary(), SASL input data
%% Descrip.: Perform one step of SASL authentication
%% Returns : {ok, Output} |
%%           {needsmore, Output} |
%%           {error, bad_instance} |
%%           {error, authentication_error}
%%           Output = binary(), SASL output data
%%--------------------------------------------------------------------
step({Pid, Instance}, Input) when is_pid(Pid),
				  is_integer(Instance),
				  is_binary(Input) ->
    call_port(Pid, {step, {Instance, Input}}).

%%--------------------------------------------------------------------
%% Function: property_get(Instance, Name)
%%           Instance = integer(), SASL instance
%%           Name = string(), Property name, one of "authid", "authzid"
%%               and "gssapi_display_name"
%% Descrip.: Get a SASL property
%% Returns : {ok, Value} |
%%           {error, bad_instance} |
%%           {error, bad_property}
%%           {error, not_found}
%%           Value = string(), SASL property value
%%--------------------------------------------------------------------
property_get({Pid, Instance}, Name) when is_pid(Pid),
					 is_integer(Instance),
					 is_atom(Name) ->
    call_port(Pid, {property_get, {Instance, Name}}).

str_error({Pid, _Instance}, Err) when is_pid(Pid),
				      is_integer(Err) ->
    call_port(Pid, {str_error, Err});
str_error(Server_ref, Err) when is_integer(Err) ->
    call_port(Server_ref, {str_error, Err}).

%%--------------------------------------------------------------------
%% Function: property_set(Instance, Name, Value)
%%           Instance = integer(), SASL instance
%%           Name = string(), Property name, one of "authid", "authzid"
%%               and "gssapi_display_name"
%%           Value = string(), SASL property value
%% Descrip.: Set a SASL property
%% Returns : {ok, set} |
%%           {error, bad_instance} |
%%           {error, bad_property}
%%--------------------------------------------------------------------
property_set({Pid, Instance}, Name, Value) when is_pid(Pid),
						is_integer(Instance),
						is_atom(Name), is_list(Value) ->
    call_port(Pid, {property_set, {Instance, Name, Value}}).

%%--------------------------------------------------------------------
%% Function: finish(Instance)
%%           Instance = integer(), SASL instance
%% Descrip.: Release SASL instance
%% Returns : {ok, finished} |
%%           {error, bad_instance}
%%--------------------------------------------------------------------
finish({Pid, Instance}) when is_pid(Pid),
			     is_integer(Instance) ->
    call_port(Pid, {finish, Instance}).

mechlist(Server_ref, Mode) ->
    case call_port(Server_ref, {mechlist, Mode}) of
	{ok, List} ->
	    {ok, string:tokens(List, " ")};
	E ->
	    E
    end.

%% Internal functions

lookup_server(Server_ref) ->
    if
	is_pid(Server_ref) -> Server_ref;
	is_atom(Server_ref) -> whereis(Server_ref)
    end.

call_port(Pid, Msg) ->
    ?INFO("call_port ~p~n", [Msg]),
    Ref = make_ref(),
    Pid ! {gsasl_call, {self(), Ref}, Msg},
    receive
	{gsasl_reply, _Pid, Ref, Result} ->
	    ?DEBUG("call_port Result ~p~n", [Result]),
	    Result
    end.

init(ServerName, KeyTab, ExtPrg, Ccname) ->
    case ServerName of
	'$anonymous' ->
	    ignore;
	{local, Name} ->
	    register(Name, self())
    end,
	    
    process_flag(trap_exit, true),
    KeyTabEnv =
	if KeyTab =/= [] ->
		[{"KRB5_KTNAME", KeyTab}];
	   true ->
		[]
	end,
    Ccname_env =
	if Ccname =/= [] ->
		[{"KRB5CCNAME", Ccname}];
	   true ->
		[]
	end,
    Env = KeyTabEnv ++ Ccname_env,
    ?INFO("port env ~p~n", [Env]),
    Port = open_port({spawn, ExtPrg}, [{packet, 2}, binary, exit_status, {env,  Env}]),
    ?INFO("port inited~n", []),
    proc_lib:init_ack(self()),
    loop(Port, []).

loop(Port, Queue) ->
    receive
	{gsasl_call, {Caller, From}, Msg} ->
	    ?DEBUG("~p: Calling port with ~p: ~p~n", [self(), Caller, Msg]),
%% 	    case Msg of
%% 		{start, _Arg} ->
%% 		    Res = link(Caller),
%% 		    ?DEBUG("link ~p~n", [Res])
%% 	    end,

	    erlang:port_command(Port, term_to_binary(Msg)),
	    Queue1 = Queue ++ [{Caller, Msg, From}],
	    loop(Port, Queue1);

	{Port, {data, Data}} ->
	    Term = binary_to_term(Data),
	    [{Caller, _Msg, From} | Queue1] = Queue,
	    ?DEBUG("~p: Result ~p: ~p~n", [self(), Caller, Term]),
	    Caller ! {gsasl_reply, self(), From, Term},
	    loop(Port, Queue1);
	{Port, {exit_status, Status}} when Status > 128 ->
	    ?ERROR("Port terminated with signal: ~p~n", [Status-128]),
	    exit({port_terminated, Status});
	{Port, {exit_status, Status}} ->
	    ?ERROR("Port terminated with status: ~p~n", [Status]),
	    exit({port_terminated, Status});
	{'EXIT', Port, Reason} ->
	    exit(Reason);
	stop ->
	    erlang:port_close(Port),
	    exit(normal);
	Term ->
	    ?ERROR("Unhandled term ~p~n", [Term])
    end,
    loop(Port, Queue).


%%====================================================================
%% Test functions
%%====================================================================

test() ->
    test(["xmpp", gethostname(), "xmpp.keytab"]).

gethostname() ->
    {ok, Name} = inet:gethostname(),
    case inet:gethostbyname(Name) of
	{ok, Hostent} when is_record(Hostent, hostent) ->
	    Hostent#hostent.h_name;
	_ ->
	    Name
    end.

test([Service, Hostname, Key_tab]) when is_list(Service),
					is_list(Hostname),
					is_list(Key_tab) ->
    process_flag(trap_exit, true),
    {ok, Pid} = start_link(Key_tab, ""),
    Test = proc_lib:start_link(?MODULE, test_init, [Pid, Service, Hostname]),
    Result =
	receive
	    {'EXIT', Test, Reason} ->
		?INFO("Result ~p ~p~n", [Test, Reason]),
		Reason;
	    E ->
		?INFO("Error ~p~n", [E])
	end,
    process_flag(trap_exit, false),
    io:format("test success~n",[]),
    stop(Pid),
    Result.

test_init(Pid, Service, Host_name) ->
    process_flag(trap_exit, true),
    Server = proc_lib:start_link(?MODULE, server_init, [Pid, Service, Host_name]),
    Client = proc_lib:start_link(?MODULE, client_init, [Pid, Service, Host_name]),
    
    Server ! {set_peer, Client},
    Client ! {set_peer, Server},
    Client ! {data, <<>>},

    proc_lib:init_ack(self()),
    test_loop(Server, Client),
    ok.

test_loop(exit, exit) ->
    ?DEBUG("Test exit~n", []),
    ok;
test_loop(Server, Client) ->
    ?DEBUG("test_loop ~p ~p~n", [Server, Client]),

    receive
	{'EXIT', Server, Reason} ->
	    ?DEBUG("Server exit ~p~n", [Reason]),
	    exit(Reason);
	{'EXIT', Client, Reason} ->
	    ?DEBUG("Client exit ~p~n", [Reason]),
	    test_loop(Server, exit);
	S ->
	    io:format("message ~p~n", [S]),
	    test_loop(Server, Client)
    end.

client_init(Pid, Service, Host_name) ->
    ?INFO("client_init ~p ~p~n", [self(), Pid]),

    {ok, Client} = client_start(Pid, "GSSAPI", Service, Host_name),
    ?INFO("client_init ~p ~p~n", [self(), Client]),
    property_set(Client, authid, "authid_foo"),
    property_set(Client, authzid, "authzid_foo"),
    property_set(Client, password, "secret"),
    proc_lib:init_ack(self()),
    sasl_loop(Client, client, undefined_client).

server_init(Pid, Service, Host_name) ->
    ?INFO("server_init ~p ~p~n", [self(), Pid]),

    {ok, Server} = server_start(Pid, "GSSAPI", Service, Host_name),
    ?INFO("server_init ~p ~p~n", [self(), Server]),
    proc_lib:init_ack(self()),
    sasl_loop(Server, server, undefined_server).

sasl_loop(Ref, Mode, Peer) ->
    receive
	{data, Data} ->
 	    ?INFO("data received~n", []),
	    sasl_data(Ref, Mode, Peer, Data),
	    sasl_loop(Ref, Mode, Peer);
	{set_peer, Peer1} ->
	    ?DEBUG("set_peer received~n", []),
	    sasl_loop(Ref, Mode, Peer1);
	stop ->
	    exit(normal)
    end.

sasl_data(Ref, Mode, Peer, Data) ->
    case step(Ref, Data) of
	{needsmore, Resp} ->
	    Peer ! {data, Resp};
	{ok, Resp} ->
	    if Resp == "" ->
		    ignore;
	       true ->
		    Peer ! {data, Resp}
	    end,
	    if Mode == server ->
		    Authid = property_get(Ref, authid),
		    Authzid = property_get(Ref, authzid),
		    Display_name = property_get(Ref, gssapi_display_name),
		    ?DEBUG("authid:~p authzid:~p display:~p~n", [Authid, Authzid, Display_name]),
		    finish(Ref),
		    exit({authenticated, Authzid, Display_name});
	       Mode == client ->
		    exit(normal)
	    end;
	{error, Reason} ->
	    exit({error, Reason})
    end.

ignore(_,_) ->
    ok.
