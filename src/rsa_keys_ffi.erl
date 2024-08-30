-module(rsa_keys_ffi).

-export([generate_rsa_key_pair/0, sign_message/2, verify_message/3]).

-include_lib("public_key/include/public_key.hrl").

generate_rsa_key_pair() ->
    % Generate RSA key pair
    PrivateKey = public_key:generate_key({rsa, 2048, 65537}),
    PublicKey =
        #'RSAPublicKey'{
            modulus = PrivateKey#'RSAPrivateKey'.modulus,
            publicExponent = PrivateKey#'RSAPrivateKey'.publicExponent
        },
    % Encode public key to PEM format
    PublicKeyDer = public_key:der_encode('RSAPublicKey', PublicKey),
    PublicKeyPem = public_key:pem_encode([{'RSAPublicKey', PublicKeyDer, not_encrypted}]),

    % Encode private key to PEM format
    PrivateKeyDer = public_key:der_encode('RSAPrivateKey', PrivateKey),
    PrivateKeyPem = public_key:pem_encode([{'RSAPrivateKey', PrivateKeyDer, not_encrypted}]),

    {PublicKeyPem, PrivateKeyPem, PublicKeyDer, PrivateKeyDer}.

sign_message(Msg, PrivateKeyDerBinary) ->
    try
        % Decode the binary DER to an RSA private key
        PrivateKey = public_key:der_decode('RSAPrivateKey', PrivateKeyDerBinary),
        % Hash the message using the chosen hash algorithm (SHA-256)
        HashedMsg = crypto:hash(sha256, Msg),

        % Sign the hashed message
        Signature = public_key:sign(HashedMsg, sha256, PrivateKey),

        % Return the signature
        {ok, Signature}
    catch
        % Catch decoding errors
        error:badarg ->
            {error, invalid_der_format};
        % Catch other potential errors
        _:Reason ->
            {error, Reason}
    end.

verify_message(Msg, PublicKeyDerBinary, Signature) ->
    try
        % Decode the binary DER to an RSA public key
        PublicKey = public_key:der_decode('RSAPublicKey', PublicKeyDerBinary),
        % Hash the message using the chosen hash algorithm (SHA-256)
        HashedMsg = crypto:hash(sha256, Msg),

        % Verify the signature
        case public_key:verify(HashedMsg, sha256, Signature, PublicKey) of
            true -> {ok, valid_signature};
            false -> {ok, invalid_signature}
        end
    catch
        % Catch decoding errors
        error:badarg ->
            {error, invalid_der_format};
        % Catch other potential errors
        _:Reason ->
            {error, Reason}
    end.
