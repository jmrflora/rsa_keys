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
  let #(pubkey, prvkey) = rsa_keys.generate_rsa_keys()
  // io.debug(pubkey)
  // io.debug(prvkey)
}
//
// pub fn sign_msg_test() {
//   let #(_pubkey, prvtkey) = rsa_keys.generate_rsa_keys()
//
//   rsa_keys.sign_message("ola mundo", prvtkey.pem)
//   |> should.be_ok
//   |> bit_array.base16_encode
//   |> io.debug
// }
// 
// pub fn verify_msg_test() {
//   let #(pubkey, prvtkey) = rsa_keys.generate_rsa_keys()
//
//   let result = {
//     use signature <- result.try(rsa_keys.sign_message("ola mundo", prvtkey))
//     rsa_keys.verify_message(
//       message: "ola mundo",
//       pubkey: pubkey,
//       sign: signature,
//     )
//   }
//   should.be_ok(result)
// }
