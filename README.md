# Cashaddr

Library for decoding and validating CashAddr btc cash addresses.
Implements CashAddr encoding and decoding specified by [Address format for Bitcoin Cash v 1.0](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
as well as CashToken aware addresses [CashToken](https://github.com/bitjson/cashtokens#cashaddress-token-support).

## Installation

The package can be installed by adding `cashaddr` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:cashaddr, "~> 0.1.0"}
  ]
end
```

## Usage

`encode` and `decode` transform CashAddr into prefix and payload.

```elixir
CashAddr.encode("prefix", "hełło")
"prefix:dpjutqk9sfhsx5tgjch6"

CashAddr.decode("bitcoincash:qph5kuz78czq00e3t85ugpgd7xmer5kr7c5f6jdpwk")
{:ok, {"bitcoincash",
        <<0, 111, 75, 112, 94, 62, 4, 7, 191, 49, 89, 233, 196, 5, 13, 241, 183, 145, 210, 195, 246>>}}
```

`encode_payload` and `decode_payload` transform payload into version and hash.

```elixir
CashAddr.encode_payload(0, <<118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>)
<<0, 118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>

CashAddr.decode_payload(<<0, 118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>)
{:ok, {0, 160, <<118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>}}
```

## Documentation

Docs can be found at [https://hexdocs.pm/cashaddr](https://hexdocs.pm/cashaddr).

## License

CashAddr source code is released under MIT License.
Check LICENSE file for more information.
