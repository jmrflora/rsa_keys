# rsa_keys

[![Package Version](https://img.shields.io/hexpm/v/rsa_keys)](https://hex.pm/packages/rsa_keys)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/rsa_keys/)

A small library to help with RSA keys.

## installation

```sh
gleam add rsa_keys
```

## example usage

```gleam
import rsa_keys

pub fn main() {
  
  let #(pubkey, prvtkey) = rsa_keys.generate_rsa_keys()

  let result = {
    use signature <- result.try(rsa_keys.sign_message("ola mundo", prvtkey))
    rsa_keys.verify_message(
      message: "ola mundo",
      pubkey: pubkey,
      sign: signature,
    )
  }
  
}
```

Further documentation can be found at <https://hexdocs.pm/rsa_keys>.

Many thanks to the discord user julian.nz in the gleam discord server for the help with the erlang ffi
