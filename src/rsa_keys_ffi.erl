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


sign_message(Msg, PrivateKeyPem) ->
    try
        % Decode the PEM-encoded private key
        PrivateKeyDerList = public_key:pem_decode(PrivateKeyPem),

        % Ensure the PEM decoding returned at least one entry
        case PrivateKeyDerList of
            [PrivateKeyDerEntry] ->
                % Extract the DER binary from the tuple
                {_, PrivateKeyDerBinary, _} = PrivateKeyDerEntry,

                % Decode the binary DER to an RSA private key
                PrivateKey = public_key:der_decode('RSAPrivateKey', PrivateKeyDerBinary),

                % Hash the message using the chosen hash algorithm (SHA-256)
                HashedMsg = crypto:hash(sha256, Msg),

                % Sign the hashed message
                Signature = public_key:sign(HashedMsg, sha256, PrivateKey),

                % Return the signature
                {ok, Signature};
            _ ->
                {error, invalid_pem_format}
        end
    catch
        % Catch decoding errors
        error:badarg ->
            {error, invalid_der_format};
        % Catch other potential errors
        _:Reason ->
            {error, Reason}
    end.

verify_message(Msg, PublicKeyPem, Signature) ->
    try
        % Decode the PEM-encoded public key
        PublicKeyDerList = public_key:pem_decode(PublicKeyPem),

        % Ensure the PEM decoding returned at least one entry
        case PublicKeyDerList of
            [PublicKeyDerEntry] ->
                % Extract the DER binary from the tuple
                {_, PublicKeyDerBinary, _} = PublicKeyDerEntry,

                % Decode the binary DER to an RSA public key
                PublicKey = public_key:der_decode('RSAPublicKey', PublicKeyDerBinary),

                % Hash the message using the chosen hash algorithm (SHA-256)
                HashedMsg = crypto:hash(sha256, Msg),

                % Verify the signature
                case public_key:verify(HashedMsg, sha256, Signature, PublicKey) of
                    true -> {ok, valid_signature};
                    false -> {error, invalid_signature}
                end;
            _ ->
                {error, invalid_pem_format}
        end
    catch
        % Catch decoding errors
        error:badarg ->
            {error, invalid_der_format};
        % Catch other potential errors
        _:Reason ->
            {error, Reason}
    end.
