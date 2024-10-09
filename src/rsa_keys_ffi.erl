-module(rsa_keys_ffi).

-export([generate_rsa_key_pair/0, sign_message/2, verify_message/3, decode_pem_to_der/1, encrypt_message/2, decrypt_message/2]).

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

decode_pem_to_der(KeyPem) ->
    try
        % Decode the PEM-encoded private key
        KeyDerList = public_key:pem_decode(KeyPem),

        % Ensure the PEM decoding returned at least one entry
        case KeyDerList of
            [{_, DerBinary, _}] ->
                % Successfully extracted DER binary from the tuple
                {ok, DerBinary};
            [] ->
                % Handle empty list (no valid PEM block found)
                {error, empty_pem_list};
            _ ->
                % Handle unexpected format
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


encrypt_message(PlainTextBinary, PublicKeyDerBinary) ->
    try
        % Decode the binary DER to an RSA public key
        PublicKey = public_key:der_decode('RSAPublicKey', PublicKeyDerBinary),


        % Compute the SHA-256 hash of the message
        Hash = crypto:hash(sha256, PlainTextBinary),

        % Append the hash to the message
        MessageWithHash = <<PlainTextBinary/binary, Hash/binary>>,

        % Encrypt the message with the public key
        EncryptedMessage = public_key:encrypt_public(MessageWithHash, PublicKey),

        {ok, EncryptedMessage}
    catch
        error:badarg -> {error, invalid_der_format};
        _:Reason -> {error, Reason}
    end.


decrypt_message(EncryptedMessage, PrivateKeyDerBinary) ->
    case try_decode_private_key(PrivateKeyDerBinary) of
        {ok, PrivateKey} ->
            try
                % Decrypt the message using the private key
                DecryptedMessageWithHash = public_key:decrypt_private(EncryptedMessage, PrivateKey),

                % Extract the message and hash (the last 32 bytes are the SHA-256 hash)
                MessageLength = byte_size(DecryptedMessageWithHash) - 32,
                <<DecryptedMessageBinary:MessageLength/binary, ExtractedHash/binary>> = DecryptedMessageWithHash,

                % Recompute the hash of the decrypted message
                RecomputedHash = crypto:hash(sha256, DecryptedMessageBinary),

                % Compare the recomputed hash with the extracted hash
                case RecomputedHash == ExtractedHash of
                    true -> {ok, DecryptedMessageBinary};  % Hashes match, message is valid
                    false -> {error, integrity}  % Hash mismatch, message was altered
                end
            catch
                error:badarg ->
                    {error, format};
                _:Reason ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.



% Helper function to decode the RSA private key
try_decode_private_key(PrivateKeyDerBinary) ->
    try
        % Decode the binary DER to an RSA private key
        PrivateKey = public_key:der_decode('RSAPrivateKey', PrivateKeyDerBinary),
        {ok, PrivateKey}
    catch
        error:badarg ->
            {error, invalid_der_format};
        _:Reason ->
            {error, Reason}
    end.
