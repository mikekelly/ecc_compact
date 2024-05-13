-module(ecc_compact_test).

-include_lib("public_key/include/public_key.hrl").
-include_lib("eunit/include/eunit.hrl").

generate_non_compliant_key() ->
    Key = public_key:generate_key({namedCurve,?secp256r1}),
    case ecc_compact:is_compact(Key) of
        {true, _} ->
            generate_non_compliant_key();
        false ->
            Key
    end.

% K256 key with an odd Y-coordinate
odd_y_secp256k1_key() ->
    {'ECPrivateKey',1,
        <<86,224,37,238,147,228,215,15,7,69,238,15,215,101,118,204,88,
          192,237,159,209,202,212,206,200,158,30,189,122,140,138,78>>,
        {namedCurve,{1,3,132,0,10}},
        <<4,198,148,223,114,141,97,92,50,2,119,52,132,135,74,86,152,
          86,151,212,196,29,141,240,191,206,136,179,113,154,21,246,
          140,47,252,2,53,108,192,138,6,133,162,195,4,177,125,160,200,
          22,102,188,89,214,120,43,115,16,60,225,91,230,34,88,185>>}.

% K256 key with an even Y-coordinate
even_y_secp256k1_key() ->
    {'ECPrivateKey',1,
        <<145,173,109,108,218,212,158,120,195,149,91,120,205,147,243,
          54,205,33,110,24,29,239,100,119,220,149,4,44,150,167,200,203>>,
        {namedCurve,{1,3,132,0,10}},
        <<4,96,208,77,104,198,60,254,164,98,63,137,248,175,65,151,142,
          67,192,223,39,122,40,162,139,152,82,181,33,130,160,232,206,
          210,81,255,21,59,227,197,245,116,226,146,87,254,223,114,215,
          77,82,108,166,10,22,186,72,85,119,155,25,100,141,231,228>>}.

odd_y_secp256r1_key() ->
    {'ECPrivateKey',1,<<86,28,246,201,158,79,65,1,49,173,240,17,129,187,26,122,219,211,61,71,120,4,61,92,250,134,31,161,67,127,32,2>>,{namedCurve,{1,2,840,10045,3,1,7}},<<4,246,247,15,236,243,77,38,142,46,8,125,142,50,233,59,197,0,99,219,238,179,76,246,234,57,45,139,127,186,240,6,131,56,253,255,132,75,65,178,138,162,246,214,39,150,78,224,136,82,211,50,141,54,1,110,187,241,77,123,167,251,185,158,83>>}.

even_y_secp256r1_key() ->
    {'ECPrivateKey',1,<<27,92,109,149,123,180,85,177,114,53,184,187,96,174,95,196,250,203,122,205,46,189,38,234,254,196,174,201,9,168,142,82>>,{namedCurve,{1,2,840,10045,3,1,7}},<<4,83,110,150,192,107,164,207,128,159,195,151,186,231,223,117,188,231,122,3,171,68,23,125,181,186,155,5,19,134,185,84,203,124,183,22,205,171,185,117,54,152,238,118,79,1,204,126,109,147,83,188,69,232,117,27,117,9,104,54,21,124,206,213,202>>}.

ecc_noncompliant_test() ->
    Key = generate_non_compliant_key(),
    ?assertNot(ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ?assertNotEqual({#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}}, ecc_compact:recover_compact_key(X)),
    ok.

ecc_compliant_test() ->
    {ok, Key, X} = ecc_compact:generate_key(),
    ?assertEqual({true, X}, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    ?assertEqual(ECPubKey, ecc_compact:recover_compact_key(X)),
    ?assertEqual({true, X}, ecc_compact:is_compact(ECPubKey)),
    ok.

wrong_curve_test() ->
    %% generate the koblitz curve
    Key = public_key:generate_key({namedCurve,?secp256k1}),
    ?assertError(badarg, ecc_compact:is_compact(Key)),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    try ecc_compact:recover_compact_key(X) of
        Result ->
            %% point happens to somehow make sense, but it should not return a sane key
            ?assertNotEqual(ECPubKey, Result)
    catch
        error:enotsup ->
            ?assert(true)
    end,
    ok.

key_with_leading_zeros_in_y_coordinate_test() ->
    Key = {'ECPrivateKey',1,
           <<24,166,124,60,235,151,150,175,21,14,17,166,20,155,69,168,147,56,
             174,143,138,64,60,78,4,101,129,96,135,46,205,204>>,
           {namedCurve,{1,2,840,10045,3,1,7}},
           <<4,216,67,1,187,4,120,72,243,120,252,76,68,11,155,208,244,56,
             101,253,67,214,128,225,88,64,204,147,185,108,176,237,19,0,109,
             55,36,142,111,190,1,48,190,235,92,27,234,62,176,156,121,37,71,
             202,191,139,227,53,139,188,53,37,254,84,33>>},
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, _Y:32/binary>> = PubKey,
    ?assertEqual(ECPubKey, ecc_compact:recover_compact_key(X)).

roundtrip_k256_odd_y_test() ->
    Key = odd_y_secp256k1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256k1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be odd
    ?assertEqual(Y rem 2, 1),
    CompressedKey = <<3, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).

roundtrip_k256_even_y_test() ->
    Key = even_y_secp256k1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256k1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be even
    ?assertEqual(Y rem 2, 0),
    CompressedKey = <<2, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).

roundtrip_p256_odd_y_test() ->
    Key = odd_y_secp256r1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be odd
    ?assertEqual(Y rem 2, 1),
    CompressedKey = <<3, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key_r1(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).

roundtrip_p256_even_y_test() ->
    Key = even_y_secp256r1_key(),
    #'ECPrivateKey'{parameters=_Params, publicKey=PubKey} = Key,
    ECPubKey = {#'ECPoint'{point=PubKey}, {namedCurve, ?secp256r1}},
    <<4, X:32/binary, Y:256>> = PubKey,
    % Y should be even
    ?assertEqual(Y rem 2, 0),
    CompressedKey = <<2, X/binary>>,
    UncompressedPubKey = ecc_compact:recover_compressed_key_r1(CompressedKey),
    ?assertEqual(UncompressedPubKey, ECPubKey).
