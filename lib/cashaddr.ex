defmodule CashAddr do
  import Bitwise

  @moduledoc ~S"""
  Encode and decode the CashAddr format, with checksums.
  """

  # Encoding character set. Maps data value -> char
  for {encoding, value} <- Enum.with_index('qpzry9x8gf2tvdw0s3jn54khce6mua7l') do
    defp do_encode32(unquote(value)), do: unquote(encoding)
    defp do_decode32(unquote(encoding)), do: unquote(value)
  end

  defp do_decode32(_), do: nil

  # Human-readable part and data part separator (':')
  @separator 0x3A

  # Generator coefficients
  for {generator_value, index} <-
        Enum.with_index([0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]) do
    defp generator(unquote(index)), do: unquote(generator_value)
  end

  @uint5_max_value 31

  # hash sizes
  for {hash_size_value, index} <- Enum.with_index([160, 192, 224, 256, 320, 384, 448, 512]) do
    defp hash_size(unquote(index)), do: unquote(hash_size_value)
    defp encode_hash_size(unquote(hash_size_value)), do: unquote(index)
  end

  defp encode_hash_size(_), do: raise(ArgumentError)

  @doc ~S"""
  Encode a CashAddr string.

  ## Examples

      iex> CashAddr.encode("prefix", "hełło")
      "prefix:dpjutqk9sfhsx5tgjch6"

      iex> CashAddr.encode("bitcoincash", <<0, 111, 75, 112, 94, 62, 4, 7, 191, 49, 89, 233, 196, 5, 13, 241, 183, 145, 210, 195, 246>>)
      "bitcoincash:qph5kuz78czq00e3t85ugpgd7xmer5kr7c5f6jdpwk"
  """
  @spec encode(String.t(), binary()) :: String.t()
  def encode(hrp, data) when is_binary(data) do
    do_encode(hrp, split(data, []))
  end

  defp do_encode(hrp, data) when is_list(data) do
    checksummed = data ++ create_checksum(hrp, data)
    dp = for i <- checksummed, into: "", do: <<do_encode32(i)>>
    <<hrp::binary, @separator, dp::binary>>
  end

  defp split(data, acc) do
    case data do
      <<a::size(5), rest::bitstring>> ->
        split(rest, acc ++ [a])

      <<a::size(4)>> ->
        acc ++ [a <<< 1]

      <<a::size(3)>> ->
        acc ++ [a <<< 2]

      <<a::size(2)>> ->
        acc ++ [a <<< 3]

      <<a::size(1)>> ->
        acc ++ [a <<< 4]

      <<>> ->
        acc
    end
  end

  @doc ~S"""
  Decode a CashAddr string.

  ## Examples

      iex> CashAddr.decode("prefix:dpjutqk9sfhsx5tgjch6")
      {:ok, {"prefix", "hełło"}}

      iex> CashAddr.decode("bitcoincash:qph5kuz78czq00e3t85ugpgd7xmer5kr7c5f6jdpwk")
      {:ok, {"bitcoincash",
        <<0, 111, 75, 112, 94, 62, 4, 7, 191, 49, 89, 233, 196, 5, 13, 241, 183, 145, 210, 195, 246>>}}
  """
  @spec decode(String.t()) :: {:ok, {String.t(), binary()}} | {:error, String.t()}
  def decode(bech) do
    with {_, false} <- {:mixed, String.downcase(bech) != bech && String.upcase(bech) != bech},
         bech_charlist = :binary.bin_to_list(bech),
         bech = String.downcase(bech),
         len = Enum.count(bech_charlist),
         pos =
           Enum.find_index(Enum.reverse(bech_charlist), fn c ->
             c == @separator
           end),
         {_, true} <- {:oor_sep, pos != nil},
         pos = len - pos - 1,
         {_, false} <- {:empty_hrp, pos < 1},
         {_, false} <- {:short_cs, pos + 9 > len},
         <<hrp::binary-size(pos), @separator, data::binary>> = bech,
         data_charlist =
           (for c <- :binary.bin_to_list(data) do
              do_decode32(c)
            end),
         {_, false} <-
           {:oor_data,
            Enum.any?(
              data_charlist,
              &match?(nil, &1)
            )},
         {_, true} <- {:cs, verify_checksum(hrp, data_charlist)},
         data_len = Enum.count(data_charlist),
         data = Enum.slice(data_charlist, 0, data_len - 8) do
      len_bits = (data_len - 8) * 5
      bits = div(len_bits, 8) * 8
      padding_length = rem(len_bits, 8)

      <<decoded::bits-size(bits), _::size(padding_length)>> =
        for d <- data, into: <<0::size(0)>>, do: <<d::size(5)>>

      {:ok, {hrp, decoded}}
    else
      {:mixed, _} -> {:error, "Mixed case"}
      {:oor_sep, _} -> {:error, "No separator character"}
      {:empty_hrp, _} -> {:error, "Empty HRP"}
      {:oor_data, _} -> {:error, "Invalid data"}
      {:short_cs, _} -> {:error, "Too short checksum"}
      {:cs, _} -> {:error, "Invalid checksum"}
      _ -> {:error, "Unknown error"}
    end
  end

  @doc ~S"""
  Encodes hash as CashAddr payload

  ## Examples

      iex> CashAddr.encode_payload(0, <<118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>)
      <<0, 118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>
  """
  def encode_payload(type, hash)
      when is_integer(type) and type >= 0 and type <= 15 and is_binary(hash) do
    encoded_hash_size = encode_hash_size(byte_size(hash) * 8)
    <<0::1, type::4, encoded_hash_size::3>> <> hash
  end

  @doc ~S"""
  Decode a CashAddr payload. Retrns tuple containing address type, hash size and hash

  ## Examples

      iex> CashAddr.decode_payload(<<0, 118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>)
      {:ok, {0, 160, <<118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178, 159, 85, 152, 115>>}}
  """
  def decode_payload(<<version_byte::binary-size(1), rest::binary>>) do
    <<reserved_bit::1, type::4, encoded_hash_size::3>> = version_byte

    with {_, true} <- {:invalid_reserved_bit, reserved_bit == 0},
         hash_size <- hash_size(encoded_hash_size),
         {_, true} <- {:invalid_hash_size, byte_size(rest) * 8 == hash_size} do
      {:ok, {type, hash_size, rest}}
    else
      {:invalid_reserved_bit, _} -> {:error, "Invalid reserved bit in version byte"}
      {:invalid_hash_size, _} -> {:error, "Invalid payload hash size"}
    end
  end

  def decode_payload(<<>>), do: {:error, "No version byte"}

  # Create a checksum.
  defp create_checksum(hrp, data) do
    payload = expand_hrp(hrp) ++ data

    values = payload ++ [0, 0, 0, 0, 0, 0, 0, 0]
    mod = polymod(values)
    for p <- 0..7, do: mod >>> (5 * (7 - p)) &&& @uint5_max_value
  end

  # Verify a checksum.
  defp verify_checksum(hrp, data) do
    polymod(expand_hrp(hrp) ++ data) == 0
  end

  # Expand a HRP for use in checksum computation.
  defp expand_hrp(hrp) do
    hrp_charlist = :binary.bin_to_list(hrp)

    b_values = for c <- hrp_charlist, do: c &&& @uint5_max_value
    b_values ++ [0]
  end

  # Find the polynomial with value coefficients mod the generator as 30-bit.
  defp polymod(data) do
    c =
      Enum.reduce(data, 1, fn d, c ->
        if d > @uint5_max_value or d < 0, do: raise(ArgumentError)
        c0 = c >>> 35
        c = bxor((c &&& 0x07FFFFFFFF) <<< 5, d)

        Enum.reduce(for(i <- 0..4, do: i), c, fn i, c ->
          g =
            if (c0 >>> i &&& 1) != 0 do
              generator(i)
            else
              0
            end

          bxor(c, g)
        end)
      end)

    bxor(c, 1)
  end
end
