import gleam/bit_array
import gleam/result
import gleeunit
import gleeunit/should
import rsa_keys

pub fn main() {
  gleeunit.main()
}

pub fn generate_key_test() {
  let #(_pubkey, _prvkey) = rsa_keys.generate_rsa_keys()
  // io.debug(pubkey)
  // io.debug(prvkey)
}

//
pub fn sign_msg_test() {
  let #(_pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  rsa_keys.sign_message(bit_array.from_string("ola mundo"), prvtkey)
  |> should.be_ok
  // |> bit_array.base16_encode
  // |> io.debug
}

pub fn verify_msg_test() {
  let #(pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  let result = {
    use signature <- result.try(rsa_keys.sign_message(
      bit_array.from_string("ola mundo"),
      prvtkey,
    ))
    rsa_keys.verify_message(
      message: bit_array.from_string("ola mundo"),
      public_key: pubkey,
      signature: signature,
    )
  }
  should.be_ok(result)
  |> should.be_true

  let result = {
    use signature <- result.try(rsa_keys.sign_message(
      bit_array.from_string("ola mundo"),
      prvtkey,
    ))
    rsa_keys.verify_message(
      message: bit_array.from_string("tchau mundo"),
      public_key: pubkey,
      signature: signature,
    )
  }
  should.be_ok(result)
  |> should.be_false
}
