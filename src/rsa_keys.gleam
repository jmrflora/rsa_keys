//// Simple and easy set of functions to generate rsa keys, sign a message and verify it, targeting erlang.
////
//// Funções simples e fáceis para gerar chaves rsa, assinar uma mensagem e verificála, usando erlang.

import gleam/bit_array
import gleam/result

pub type PrivateKey {
  PrivateKey(der: BitArray, pem: String)
}

pub type PublicKey {
  PublicKey(der: BitArray, pem: String)
}

type SignatureType {
  ValidSignature
  InvalidSignature
}

@external(erlang, "rsa_keys_ffi", "decode_pem_to_der")
fn do_decode_pem_to_der(
  pem_encoded_key key: BitArray,
) -> Result(BitArray, String)

/// Decode a pem key to a der binary
pub fn decode_pem_to_der(
  pem_encoded_key key: String,
) -> Result(BitArray, String) {
  do_decode_pem_to_der(bit_array.from_string(key))
}

@external(erlang, "rsa_keys_ffi", "generate_rsa_key_pair")
fn do_generate_rsa_keys() -> #(String, String, BitArray, BitArray)

/// Generate public and private RSA key pairs.
///
/// The pem records are PEM encoded and thus human readable.
pub fn generate_rsa_keys() {
  let #(pubkeypem, prvtkeypem, pubkeyder, prvtkeyder) = do_generate_rsa_keys()
  let pubkey = PublicKey(pubkeyder, pubkeypem)
  let prvtkey = PrivateKey(prvtkeyder, prvtkeypem)
  #(pubkey, prvtkey)
}

@external(erlang, "rsa_keys_ffi", "sign_message")
fn do_sign_message(
  message msg: BitArray,
  privatekey privatekey: BitArray,
) -> Result(BitArray, String)

/// Hash a message using sha256 and sign it using a private key.
///
/// The returned signature can then be base16 encoded for readability.
pub fn sign_message(message msg: BitArray, private_key prvtkey: PrivateKey) {
  do_sign_message(msg, prvtkey.der)
}

/// Same as sign_message but uses pem string as the argument.
pub fn sign_message_with_pem_string(
  message msg: BitArray,
  private_key_pem prvtkey_pem: String,
) {
  use private_key_der <- result.try(decode_pem_to_der(prvtkey_pem))
  do_sign_message(msg, private_key_der)
}

@external(erlang, "rsa_keys_ffi", "verify_message")
fn do_verify_message(
  msg: BitArray,
  pubkey: BitArray,
  sign: BitArray,
) -> Result(SignatureType, String)

/// verify a message against its sha256 hash and signature using a public key.
///
/// returns a Ok(True) for valid signature
///
/// returns a Ok(False) for invalid signature
///
/// returns an Error for runtime issues.
pub fn verify_message(
  message msg: BitArray,
  public_key public_key: PublicKey,
  signature signature: BitArray,
) {
  case do_verify_message(msg, public_key.der, signature) {
    Ok(ValidSignature) -> Ok(True)
    Ok(InvalidSignature) -> Ok(False)
    Error(reason) -> Error(reason)
  }
}

/// Same as verify_message but with pem string as the argument.
pub fn verify_message_with_pem_string(
  message msg: BitArray,
  public_key_pem_string public_key_pem: String,
  signature signature: BitArray,
) {
  case decode_pem_to_der(public_key_pem) {
    Ok(public_key_der) -> {
      case do_verify_message(msg, public_key_der, signature) {
        Ok(ValidSignature) -> Ok(True)
        Ok(InvalidSignature) -> Ok(False)
        Error(reason) -> Error(reason)
      }
    }
    Error(reason) -> Error(reason)
  }
}
