-module(aest_nodes).

%=== EXPORTS ===================================================================

%% Common Test API exports
-export([ct_setup/1]).
-export([ct_cleanup/1]).

%% QuickCheck API exports
-export([eqc_setup/2]).
-export([eqc_cleanup/0]).

%% Generic API exports
-export([setup_nodes/1]).
-export([start_node/1]).
-export([stop_node/2]).
-export([kill_node/1]).
-export([extract_archive/3]).
-export([run_cmd_in_node_dir/2]).
-export([run_cmd_in_node_dir/3]).
-export([connect_node/2]).
-export([disconnect_node/2]).
-export([get_service_address/2]).
-export([get_node_pubkey/1]).
-export([http_get/4]).
-export([http_post/6]).

%% Helper function exports
-export([request/3]).
-export([get/4]).
-export([get_block/2]).
-export([get_top/1]).
-export([wait_for_value/3]).

%=== MACROS ====================================================================

-define(BACKENDS, [aest_docker]).
-define(CALL_TAG, ?MODULE).
-define(CT_CONF_KEY, node_manager).
-define(CALL_TIMEOUT, 60000).
-define(NODE_TEARDOWN_TIMEOUT, 0).
-define(DEFAULT_HTTP_TIMEOUT, 3000).

%=== TYPES ====================================================================

-type node_service() :: ext_http | int_http | int_ws.
-type http_path() :: [atom() | binary() | number()] | binary().
-type http_query() :: #{atom() | binary() => atom() | binary()}.
-type http_headers() :: [{binary(), binary()}].
-type http_body() :: binary().
-type json_object() :: term().
-type milliseconds() :: non_neg_integer().
-type path() :: binary() | string().
-type peer_spec() :: atom() | binary().

-type node_spec() :: #{
    % The unique name of the node
    name    := atom(),
    % If peer is given as an atom it is expected to be a node name,
    % if given as a binary it is expected to be the external URL of the peer.
    peers   := [peer_spec()],
    backend := aest_docker,

%% When `backend` is `aest_docker`:

    % The source of the docker image
    source  := {pull, binary() | string()},
    % Public/private peer key can be specified explicity for the node.
    % Both are required and will be saved, overriding any present keys.
    pubkey => binary(),
    privkey => binary()
}.

%=== COMMON TEST API FUNCTIONS =================================================

%% @doc Setups the the node manager for Common Test.
-spec ct_setup(proplists:proplist()) -> proplists:proplist().
ct_setup(Config) ->
    {data_dir, DataDir} = proplists:lookup(data_dir, Config),
    {priv_dir, PrivDir} = proplists:lookup(priv_dir, Config),
    ct:log("Node logs can be found here: ~n<a href=\"file://~s\">~s</a>",
        [PrivDir, PrivDir]
    ),
    LogFun = fun(Fmt, Args) -> ct:log(Fmt, Args) end,
    case aest_nodes_mgr:start([aest_docker], #{ test_id => uid(),
                                                log_fun => LogFun,
                                                data_dir => DataDir,
                                                temp_dir => PrivDir}) of
        {ok, Pid} -> [{?CT_CONF_KEY, Pid} | Config];
        {error, Reason} ->
            erlang:error({system_test_setup_failed, [{reason, Reason}]})
    end.

%% @doc Stops the node manager and all the nodes that were started.
%% If the nodes log contains errors it will print the error lines and
%% ann error will be thrown.
-spec ct_cleanup(proplists:proplist()) -> ok.
ct_cleanup(_Config) ->
    check_call(aest_nodes_mgr:dump_logs()),
    Result = scan_logs_for_errors(),
    check_call(aest_nodes_mgr:cleanup()),
    check_call(aest_nodes_mgr:stop()),
    wait_for_exit(120000),
    case Result of
        {error, Reason} -> erlang:error(Reason);
        ok -> ok
    end.

%=== QICKCHECK API FUNCTIONS ===================================================

%% @doc Setups the node manager for Quick Check tests.
-spec eqc_setup(path(), path()) -> pid().
eqc_setup(DataDir, TempDir) ->
    case aest_nodes_mgr:start([aest_docker], #{data_dir => DataDir, temp_dir => TempDir}) of
        {ok, Pid} -> Pid;
        {error, Reason} ->
            erlang:error({system_test_setup_failed, [{reason, Reason}]})
    end.

%% @doc Stops the node manager for QuickCheck tests.
%% If the nodes log contains errors it will print the error lines and
%% ann error will be thrown.
-spec eqc_cleanup() -> ok.
eqc_cleanup() ->
    Result = scan_logs_for_errors(),
    check_call(aest_nodes_mgr:cleanup()),
    check_call(aest_nodes_mgr:stop()),
    wait_for_exit(120000),
    case Result of
        {error, Reason} -> erlang:error(Reason);
        ok -> ok
    end.

%=== GENERIC API FUNCTIONS =====================================================

%% @doc Creates and setups a list of nodes.
%% The nodes are not started, use `start_node/2` for that.
-spec setup_nodes([node_spec()]) -> ok.
setup_nodes(NodeSpecs) ->
    check_call(aest_nodes_mgr:setup_nodes(NodeSpecs)).

%% @doc Starts a node previously setup.
-spec start_node(atom()) -> ok.
start_node(NodeName) ->
    check_call(aest_nodes_mgr:start_node(NodeName)).

%% @doc Stops a node previously started with explicit timeout (in milliseconds)
%% after which the node will be killed.
-spec stop_node(atom(), milliseconds() | infinity) -> ok.
stop_node(NodeName, Timeout) ->
    check_call(aest_nodes_mgr:stop_node(NodeName, Timeout)).

%% @doc Kills a node.
-spec kill_node(atom()) -> ok.
kill_node(NodeName) ->
    check_call(aest_nodes_mgr:kill_node(NodeName)).

extract_archive(NodeName, Path, Archive) ->
    check_call(aest_nodes_mgr:extract_archive(NodeName, Path, Archive)).

run_cmd_in_node_dir(NodeName, Cmd) ->
    check_call(aest_nodes_mgr:run_cmd_in_node_dir(NodeName, Cmd, 5000)).

run_cmd_in_node_dir(NodeName, Cmd, Timeout) ->
    check_call(aest_nodes_mgr:run_cmd_in_node_dir(NodeName, Cmd, Timeout)).

%% @doc Connect a node to a network.
-spec connect_node(atom(), atom()) -> ok.
connect_node(NodeName, NetName) ->
    check_call(aest_nodes_mgr:connect_node(NodeName, NetName)).

%% @doc Disconnect a node from a network.
-spec disconnect_node(atom(), atom()) -> ok.
disconnect_node(NodeName, NetName) ->
    check_call(aest_nodes_mgr:disconnect_node(NodeName, NetName)).

%% @doc Retrieves the address of a given node's service.
-spec get_service_address(atom(), node_service()) -> binary().
get_service_address(NodeName, Service) ->
    check_call(aest_nodes_mgr:get_service_address(NodeName, Service)).

-spec get_node_pubkey(atom()) -> binary().
get_node_pubkey(NodeName) ->
    check_call(aest_nodes_mgr:get_node_pubkey(NodeName)).

%% @doc Performs and HTTP get on a node service (ext_http or int_http).
-spec http_get(atom(), ext_http | int_http, http_path(), http_query()) ->
        {ok, pos_integer(), json_object()} | {error, term()}.
http_get(NodeName, Service, Path, Query) ->
    Addr = get_service_address(NodeName, Service),
    http_addr_get(Addr, Path, Query).

-spec http_post(atom(), ext_http | int_http, http_path(), http_query(), http_headers(), http_body()) ->
        {ok, pos_integer(), json_object()} | {error, term()}.
http_post(NodeName, Service, Path, Query, Headers, Body) ->
    Addr = get_service_address(NodeName, Service),
    http_addr_post(Addr, Path, Query, Headers, Body).

%=== HELPER FUNCTIONS ==========================================================

%% @doc Performs an HTTP get request on the node external API.
%% Should preferably use `get/5` with service `ext_http`.
-spec request(atom(), http_path(), http_query()) -> json_object().
request(NodeName, Path, Query) ->
    get(NodeName, ext_http, Path, Query).

%% @doc Performs an HTTP get request on a node HTTP service.
-spec get(atom(), int_http | ext_http, http_path(), http_query()) -> json_object().
get(NodeName, Service, Path, Query) ->
    case http_get(NodeName, Service, Path, Query) of
        {ok, 200, Response} -> Response;
        {ok, Status, _Response} -> error({unexpected_status, Status});
        {error, Reason} -> error({http_error, Reason})
    end.

%% @doc Retrieves a block at given height from the given node.
%% It will throw an excpetion if the block does not exists.
-spec get_block(atom(), non_neg_integer()) -> json_object().
get_block(NodeName, Height) ->
    case http_get(NodeName, ext_http, [v2, 'block-by-height'], #{height => Height}) of
        {ok, 200, Response} -> Response;
        {ok, Status, _Response} -> error({unexpected_status, Status});
        {error, Reason} -> error({http_error, Reason})
    end.

%% @doc Retrieves the top block from the given node.
-spec get_top(atom()) -> json_object().
get_top(NodeName) ->
    case http_get(NodeName, ext_http, [v2, 'top'], #{}) of
        {ok, 200, Response} -> Response;
        {ok, Status, _Response} -> error({unexpected_status, Status});
        {error, Reason} -> error({http_error, Reason})
    end.

-spec wait_for_value({balance, binary(), non_neg_integer()}, [atom()], milliseconds()) -> ok;
                    ({height, non_neg_integer()}, [atom()], milliseconds()) -> ok.
wait_for_value({balance, PubKey, MinBalance}, NodeNames, Timeout) ->
    Addrs = [get_service_address(N, ext_http) || N <- NodeNames],
    Expiration = make_expiration(Timeout),
    CheckF =
        fun(Addr) ->
                case http_addr_get(Addr, [v2, account, balance, PubKey], #{}) of
                    {ok, 200, #{balance := Balance}} when Balance >= MinBalance -> done;
                    _ -> wait
                end
        end,
    wait_for_value(CheckF, Addrs, [], 500, Expiration);
wait_for_value({height, MinHeight}, NodeNames, Timeout) ->
    Start = erlang:system_time(millisecond),
    Addrs = [get_service_address(N, ext_http) || N <- NodeNames],
    Expiration = make_expiration(Timeout),
    CheckF =
        fun(Addr) ->
                case http_addr_get(Addr, [v2, 'block-by-height'], #{height => MinHeight}) of
                    {ok, 200, _} -> done;
                    _ -> wait
                end
        end,
    wait_for_value(CheckF, Addrs, [], 500, Expiration),
    Duration = (erlang:system_time(millisecond) - Start) / 1000,
    aest_nodes_mgr:log("Height ~p reached on nodes ~p after ~.2f seconds",
                       [MinHeight, NodeNames, Duration]
    ).



%=== INTERNAL FUNCTIONS ========================================================

uid() ->
    iolist_to_binary([[io_lib:format("~2.16.0B",[X])
                       || <<X:8>> <= crypto:strong_rand_bytes(8) ]]).

check_call({'$error', Reason, Stacktrace}) ->
    erlang:raise(throw, Reason, Stacktrace);
check_call(Reply) ->
    Reply.

wait_for_exit(Timeout) ->
    case aest_nodes_mgr:wait_for_exit(Timeout) of
        {error, Reason} -> error(Reason);
        ok -> ok
    end.

make_expiration(Timeout) ->
    {os:timestamp(), Timeout}.

assert_expiration({StartTime, Timeout}) ->
    Now = os:timestamp(),
    Delta = timer:now_diff(Now, StartTime),
    case Delta > (Timeout * 1000) of
        true -> error(timeout);
        false -> ok
    end.

wait_for_value(_CheckF, [], [], _Delay, _Expiration) -> ok;
wait_for_value(CheckF, [], Rem, Delay, Expiration) ->
    assert_expiration(Expiration),
    timer:sleep(Delay),
    wait_for_value(CheckF, lists:reverse(Rem), [], Delay, Expiration);
wait_for_value(CheckF, [Addr | Addrs], Rem, Delay, Expiration) ->
    case CheckF(Addr) of
        done -> wait_for_value(CheckF, Addrs, Rem, Delay, Expiration);
        wait -> wait_for_value(CheckF, Addrs, [Addr | Rem], Delay, Expiration)
    end.

http_addr_get(Addr, Path, Query) ->
    http_send(get, Addr, Path, Query, [], <<>>, #{}).

http_addr_post(Addr, Path, Query, Headers, Body) ->
    http_send(post, Addr, Path, Query, Headers, Body, #{}).

http_send(Method, Addr, Path, Query, Headers, Body, Opts) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_HTTP_TIMEOUT),
    HttpOpts = [{recv_timeout, Timeout}],
    case hackney:request(Method, url(Addr, Path, Query), Headers, Body, HttpOpts) of
        {error, _Reason} = Error -> Error;
        {ok, Status, _RespHeaders, ClientRef} ->
            case hackney_json_body(ClientRef) of
                {error, _Reason} = Error -> Error;
                {ok, Response} -> {ok, Status, Response}
            end
    end.

url(Base, Path, QS) when is_list(Path) ->
    hackney_url:make_url(Base, [to_binary(P) || P <- Path], maps:to_list(QS));
url(Base, Item, QS) ->
    url(Base, [Item], QS).

to_binary(Term) when is_atom(Term) -> atom_to_binary(Term, utf8);
to_binary(Term) when is_integer(Term) -> integer_to_binary(Term);
to_binary(Term)                    -> Term.

hackney_json_body(ClientRef) ->
    case hackney:body(ClientRef) of
        {error, _Reason} = Error -> Error;
        {ok, BodyJson} -> decode(BodyJson)
    end.

decode(<<>>) -> {ok, undefined};
decode(Data) -> decode_json(Data).

decode_json(Data) ->
    try jsx:decode(Data, [{labels, attempt_atom}, return_maps]) of
        JsonObj -> {ok, JsonObj}
    catch
        error:badarg -> {error, {bad_json, Data}}
    end.

scan_logs_for_errors() ->
    Logs = aest_nodes_mgr:get_log_paths(),
    maps:fold(fun(NodeName, LogPath, Result) ->
        LogFile = binary_to_list(filename:join(LogPath, "epoch.log")),
        case filelib:is_file(LogFile) of
            false -> Result;
            true ->
                Command = "grep '\\[error\\]' '" ++ LogFile ++ "'",
                case os:cmd(Command) of
                    "" -> Result;
                    ErrorLines ->
                        aest_nodes_mgr:log("Node ~p's logs contains errors:~n~s",
                                           [NodeName, ErrorLines]),
                        {error, log_errors}
                end
        end
    end, ok, Logs).
