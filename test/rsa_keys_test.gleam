import gleam/bit_array
import gleam/io
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

pub fn pem_to_der_test() {
  let #(_pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  rsa_keys.decode_pem_to_der(prvtkey.pem)
  |> should.be_ok

  rsa_keys.decode_pem_to_der("aaaa")
  |> should.be_error
}

pub fn sign_msg_test() {
  let #(_pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  let resultado = {
    rsa_keys.sign_message(bit_array.from_string("ola mundo"), prvtkey)
    |> should.be_ok
    |> bit_array.base16_encode
  }

  rsa_keys.sign_message_with_pem_string(
    bit_array.from_string("ola mundo"),
    prvtkey.pem,
  )
  |> should.be_ok
  |> bit_array.base16_encode
  |> should.equal(resultado)

  rsa_keys.sign_message_with_pem_string(
    bit_array.from_string("tchau mundo"),
    prvtkey.pem,
  )
  |> should.be_ok
  |> bit_array.base16_encode
  |> should.not_equal(resultado)
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

pub fn encrypt_message_test() {
  let #(pubkey, _prvtkey) = rsa_keys.generate_rsa_keys()

  io.debug("here")
  rsa_keys.encrypt_message(bit_array.from_string("ola"), pubkey)
  |> bit_array.base16_encode
  |> io.debug
}

pub fn decrypt_message_test() {
  let #(pubkey, prvtkey) = rsa_keys.generate_rsa_keys()
  let msg = rsa_keys.encrypt_message(bit_array.from_string("ola"), pubkey)

  rsa_keys.decrypt_message(msg, prvtkey)
  |> should.be_ok
  |> bit_array.to_string
  |> should.be_ok
  |> io.debug

  let #(pubkey2, _prvtkey2) = rsa_keys.generate_rsa_keys()
  let msg2 = rsa_keys.encrypt_message(bit_array.from_string("ola"), pubkey2)

  rsa_keys.decrypt_message(msg2, prvtkey)
  |> should.be_error
  |> io.debug
}

pub fn verify_message_pem_string_test() {
  let #(pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  let result = {
    use signature <- result.try(rsa_keys.sign_message_with_pem_string(
      bit_array.from_string("ola mundo"),
      prvtkey.pem,
    ))
    rsa_keys.verify_message_with_pem_string(
      message: bit_array.from_string("ola mundo"),
      public_key_pem_string: pubkey.pem,
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
    rsa_keys.verify_message_with_pem_string(
      message: bit_array.from_string("tchau mundo"),
      public_key_pem_string: pubkey.pem,
      signature: signature,
    )
  }
  should.be_ok(result)
  |> should.be_false

  let result = {
    use signature <- result.try(rsa_keys.sign_message(
      bit_array.from_string("ola mundo"),
      prvtkey,
    ))
    rsa_keys.verify_message_with_pem_string(
      message: bit_array.from_string("tchau mundo"),
      public_key_pem_string: "pempem",
      signature: signature,
    )
  }
  should.be_error(result)
}
