//// Simple and easy set of functions to generate rsa keys, sign a message and verify it, targeting erlang.
//// funções simples e fáceis para gerar chaves rsa, assinar uma mensagem e verificála, usando erlang.

/// Generate public and private RSA key pairs
/// the returned strings are PEM formated
@external(erlang, "rsa_keys_ffi", "generate_rsa_key_pair")
pub fn generate_rsa_keys() -> #(String, String)

/// hash a message using sha256 and sign it using a pem encoded private key
@external(erlang, "rsa_keys_ffi", "sign_message")
pub fn sign_message(
  message msg: String,
  prvtkey privatekey: String,
) -> Result(String, String)

/// verify a message against its sha256 hash and signature using a pem encoded public key
@external(erlang, "rsa_keys_ffi", "verify_message")
pub fn verify_message(
  message msg: String,
  pubkey public_key: String,
  sign signature: String,
) -> Result(String, String)
