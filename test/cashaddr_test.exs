defmodule CashAddrTest do
  use ExUnit.Case
  doctest CashAddr

  test "encoded data can be decoded" do
    payloads = [
      "",
      "a",
      "ą",
      "cwc",
      "#FSXCłłęaą",
      "qc3xqxwdxe3dsfc∑∂™",
      "iusdnciqednc3enciojdmcoiqencosdmc3r2ncdecn283nciehf8723hnfciqwdc09283ncqiwdocn2938rfnc"
    ]

    for a <- payloads do
      assert encoded = CashAddr.encode("p", a)
      assert {:ok, {"p", ^a}} = CashAddr.decode(encoded)
    end
  end

  test "cashaddr spec test vectors can be decoded and checksum verifies" do
    valid = [
      "prefix:x64nx6hz",
      "p:gpf8m4h7",
      "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
      "bchtest:testnetaddress4d6njnut",
      "bchreg:555555555555555555555555555555555555555555555udxmlmrz"
    ]

    for a <- valid do
      assert {:ok, {_prefix, _data}} = a |> CashAddr.decode()
    end
  end

  # some test vectors from spec are broken - they have invelid hash lengths
  @test_vector [
    {20, 0, "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
     "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
    {20, 1, "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
     "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
    # {20, 0, "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5", "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
    {20, 15, "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
     "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9"},
    {24, 0, "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
     "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
    {24, 1, "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
     "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
    # {24, 0, "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v", "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
    {24, 15, "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
     "7ADBF6C17084BC86C1706827B41A56F5CA32865925E946EA"},
    {28, 0, "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
     "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
    {28, 1, "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
     "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
    # {28, 0, "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn", "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
    {28, 15, "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
     "3A84F9CF51AAE98A3BB3A78BF16A6183790B18719126325BFC0C075B"},
    {32, 0, "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
     "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
    {32, 1, "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
     "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
    # {32, 0, "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9", "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
    {32, 15, "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
     "3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060"},
    {40, 0,
     "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
     "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
    {40, 1, "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
     "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
    # {40, 0, "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3", "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
    {40, 15, "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
     "C07138323E00FA4FC122D3B85B9628EA810B3F381706385E289B0B25631197D194B5C238BEB136FB"},
    {48, 0,
     "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
     "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
    {48, 1,
     "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
     "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
    # {48, 0, "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg", "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
    {48, 15,
     "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
     "E361CA9A7F99107C17A622E047E3745D3E19CF804ED63C5C40C6BA763696B98241223D8CE62AD48D863F4CB18C930E4C"},
    # {56, 1, "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
    {56, 1,
     "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
     "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
    # {56, 0, "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl", "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
    {56, 15,
     "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
     "D9FA7C4C6EF56DC4FF423BAAE6D495DBFF663D034A72D1DC7D52CBFE7D1E6858F9D523AC0A7A5C34077638E4DD1A701BD017842789982041"},
    {64, 0,
     "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
     "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
    {64, 1,
     "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
     "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
    # {64, 0, "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8", "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"},
    {64, 15,
     "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
     "D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B"}
  ]
  test "cashaddr spec test vectors can be decoded" do
    for {hash_size_bytes, type, address, hash_hex} <- @test_vector do
      prefix = address |> String.split(":") |> hd
      assert {:ok, {^prefix, data}} = address |> CashAddr.decode()
      hash_size = hash_size_bytes * 8
      hash = Base.decode16!(hash_hex)

      assert {:ok, {^type, ^hash_size, ^hash}} = data |> CashAddr.decode_payload()
      encoded_data = CashAddr.encode_payload(type, hash)
      assert encoded_data == data
      assert CashAddr.encode(prefix, data) == address
    end
  end

  test "valid btc cash addresses can be decoded" do
    valid =
      [
        "bitcoincash:qph5kuz78czq00e3t85ugpgd7xmer5kr7c5f6jdpwk",
        "bitcoincash:qpxenfpcf975gxdjmq9pk3xm6hjmfj6re56t60smsm",
        "bitcoincash:qzfau6vrq980qntgp5e7l6cpfsf7jw88c5u7y85qx6",
        "bitcoincash:qzcguejjfxld867ck4zudc9a6y8mf6ftgqqrxzfmlh",
        "bitcoincash:qqm2lpqdfjsg8kkhwk0a3e3gypyswkd69urny99j70",
        "bitcoincash:qrccfa4qm3xfcrta78v7du75jjaww0ylnss5nxsy9s",
        "bitcoincash:qqdcsl6c879esyxyacmz7g6vtzwjjwtznsv65x6znz",
        "bitcoincash:qpr2ddwe8qnnh8h20mmn4zgrharmy0vuy5y4gr8gl2",
        "bitcoincash:qqymsmh0nhfhs9k5whhnjwfxyaumvtxm8g2z0s4f9y",
        "bitcoincash:qzwdmm83qjx7372wxgszaukan73ffn8ct54v6hs3dl",
        "bitcoincash:qzh3f9me5z5sn2w8euap2gyrp6kr7gf6my5mhjey6s",
        "bitcoincash:qrneuckcx69clprn4nnr82tf8sycqrs3ac4tr8m86f",
        "bitcoincash:qz742xef07g9w8q52mx0q6m9hp05hnzm657wqd0ce2",
        "bitcoincash:qq5dzl0drx8v0layyyuh5aupvxfs80ydmsp5444280",
        "bitcoincash:qpxedxtug7kpwd6tgf5vx08gjamel7sldsc40mxew8",
        "bitcoincash:qr4fs2m8tjmw54r2aqmadggzuagttkujgyrjs5d769",
        "bitcoincash:qrmed4fxlhkgay9nxw7zn9muew5ktkyjnuuawvycze",
        "bitcoincash:qqv3cpvmu4h0vqa6aly0urec7kwtuhe49yz6e7922v",
        "bitcoincash:qr39scfteeu5l573lzerchh6wc4cqkxeturafzfkk9",
        "bitcoincash:qzzjgw37vwls805c9fw6g9vqyupadst6wgmane0s4l"
      ] ++
        [
          "bitcoincash:pph5kuz78czq00e3t85ugpgd7xmer5kr7crv8a2z4t",
          "bitcoincash:ppxenfpcf975gxdjmq9pk3xm6hjmfj6re5dw8qhctx",
          "bitcoincash:pzfau6vrq980qntgp5e7l6cpfsf7jw88c5tmegnra8",
          "bitcoincash:pzcguejjfxld867ck4zudc9a6y8mf6ftgqhxmdwcy2",
          "bitcoincash:pqm2lpqdfjsg8kkhwk0a3e3gypyswkd69u5ke2z39j",
          "bitcoincash:prccfa4qm3xfcrta78v7du75jjaww0ylns83wfh87d",
          "bitcoincash:pqdcsl6c879esyxyacmz7g6vtzwjjwtznsmlffapgl",
          "bitcoincash:ppr2ddwe8qnnh8h20mmn4zgrharmy0vuy5ns4vqtyh",
          "bitcoincash:pqymsmh0nhfhs9k5whhnjwfxyaumvtxm8ga8jlj27e",
          "bitcoincash:pzwdmm83qjx7372wxgszaukan73ffn8ct5zf8chjkz",
          "bitcoincash:pzh3f9me5z5sn2w8euap2gyrp6kr7gf6myr72a78pd",
          "bitcoincash:prneuckcx69clprn4nnr82tf8sycqrs3aczw7guyp5",
          "bitcoincash:pz742xef07g9w8q52mx0q6m9hp05hnzm65ftazgmzh",
          "bitcoincash:pq5dzl0drx8v0layyyuh5aupvxfs80ydmsk3g6jfuj",
          "bitcoincash:ppxedxtug7kpwd6tgf5vx08gjamel7slds0sj5p646",
          "bitcoincash:pr4fs2m8tjmw54r2aqmadggzuagttkujgy5hdm2apc",
          "bitcoincash:prmed4fxlhkgay9nxw7zn9muew5ktkyjnutcnrrmey",
          "bitcoincash:pqv3cpvmu4h0vqa6aly0urec7kwtuhe49y4ly3zf33",
          "bitcoincash:pr39scfteeu5l573lzerchh6wc4cqkxetu5c5dw4dc",
          "bitcoincash:pzzjgw37vwls805c9fw6g9vqyupadst6wgvcwkgnwz"
        ] ++
        [
          "bchtest:qph5kuz78czq00e3t85ugpgd7xmer5kr7csm740kf2",
          "bchtest:qpxenfpcf975gxdjmq9pk3xm6hjmfj6re57e7gjvh8",
          "bchtest:qzfau6vrq980qntgp5e7l6cpfsf7jw88c5cvqqkhpx",
          "bchtest:qzcguejjfxld867ck4zudc9a6y8mf6ftgqy3z9tvct",
          "bchtest:qqm2lpqdfjsg8kkhwk0a3e3gypyswkd69u8pqz89en",
          "bchtest:qrccfa4qm3xfcrta78v7du75jjaww0ylns5xhpjnzv",
          "bchtest:qqdcsl6c879esyxyacmz7g6vtzwjjwtznsggspc457",
          "bchtest:qpr2ddwe8qnnh8h20mmn4zgrharmy0vuy5q8vy9lck",
          "bchtest:qqymsmh0nhfhs9k5whhnjwfxyaumvtxm8gwsthh7zc",
          "bchtest:qzwdmm83qjx7372wxgszaukan73ffn8ct5377sjx2r",
          "bchtest:qzh3f9me5z5sn2w8euap2gyrp6kr7gf6mysfn4mnav",
          "bchtest:qrneuckcx69clprn4nnr82tf8sycqrs3ac3e8qesa4",
          "bchtest:qz742xef07g9w8q52mx0q6m9hp05hnzm656uy2d07k",
          "bchtest:qq5dzl0drx8v0layyyuh5aupvxfs80ydms9x3jhaqn",
          "bchtest:qpxedxtug7kpwd6tgf5vx08gjamel7sldsu8tuywfm",
          "bchtest:qr4fs2m8tjmw54r2aqmadggzuagttkujgy8q5n0fae",
          "bchtest:qrmed4fxlhkgay9nxw7zn9muew5ktkyjnuc02tx099",
          "bchtest:qqv3cpvmu4h0vqa6aly0urec7kwtuhe49yxgae8ads",
          "bchtest:qr39scfteeu5l573lzerchh6wc4cqkxetu80d9tp3e",
          "bchtest:qzzjgw37vwls805c9fw6g9vqyupadst6wgl0h7d8jr"
        ] ++
        [
          "bchtest:pph5kuz78czq00e3t85ugpgd7xmer5kr7c87r6g4jh",
          "bchtest:ppxenfpcf975gxdjmq9pk3xm6hjmfj6re5fur840v6",
          "bchtest:pzfau6vrq980qntgp5e7l6cpfsf7jw88c50fa0356m",
          "bchtest:pzcguejjfxld867ck4zudc9a6y8mf6ftgqn5l2v0rk",
          "bchtest:pqm2lpqdfjsg8kkhwk0a3e3gypyswkd69usyadqxzw",
          "bchtest:prccfa4qm3xfcrta78v7du75jjaww0ylnsrr2w4se3",
          "bchtest:pqdcsl6c879esyxyacmz7g6vtzwjjwtznslddwlk0r",
          "bchtest:ppr2ddwe8qnnh8h20mmn4zgrharmy0vuy5hz3tzurt",
          "bchtest:pqymsmh0nhfhs9k5whhnjwfxyaumvtxm8ge4kcsae9",
          "bchtest:pzwdmm83qjx7372wxgszaukan73ffn8ct5xmrl4937",
          "bchtest:pzh3f9me5z5sn2w8euap2gyrp6kr7gf6my8vw6usx3",
          "bchtest:prneuckcx69clprn4nnr82tf8sycqrs3acxu607nxg",
          "bchtest:pz742xef07g9w8q52mx0q6m9hp05hnzm65dee92v9t",
          "bchtest:pq5dzl0drx8v0layyyuh5aupvxfs80ydmsjrvas7mw",
          "bchtest:ppxedxtug7kpwd6tgf5vx08gjamel7sldstzknrdjx",
          "bchtest:pr4fs2m8tjmw54r2aqmadggzuagttkujgys9fug2xy",
          "bchtest:prmed4fxlhkgay9nxw7zn9muew5ktkyjnu02hypv7c",
          "bchtest:pqv3cpvmu4h0vqa6aly0urec7kwtuhe49y3dqkq7kd",
          "bchtest:pr39scfteeu5l573lzerchh6wc4cqkxetus2s2vz2y",
          "bchtest:pzzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7"
        ]

    for a <- valid do
      assert {:ok, {prefix, data}} = a |> CashAddr.decode()
      assert {:ok, {type, _, hash}} = data |> CashAddr.decode_payload()
      encoded_data = CashAddr.encode_payload(type, hash)
      assert encoded_data == data
      assert CashAddr.encode(prefix, data) == a
    end
  end

  test "validation" do
    assert {:error, "Empty HRP"} =
             ":pzzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7" |> CashAddr.decode()

    assert {:error, "No separator character"} =
             "bchtest1pzzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7" |> CashAddr.decode()

    assert {:error, "Invalid checksum"} =
             "bchtest:pzzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf8" |> CashAddr.decode()

    assert {:error, "Mixed case"} =
             "bchtest:Pzzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7" |> CashAddr.decode()

    assert {:error, "Invalid data"} =
             "bchtest:izzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7" |> CashAddr.decode()

    assert {:error, "Invalid data"} =
             "bchtest:ązzjgw37vwls805c9fw6g9vqyupadst6wgg2232yf7" |> CashAddr.decode()

    assert {:error, "No separator character"} = "" |> CashAddr.decode()
    assert {:error, "Too short checksum"} = "p:gpf8m4h" |> CashAddr.decode()
  end

  test "payload validation" do
    assert {:error, "Invalid payload hash size"} ==
             CashAddr.decode_payload(
               <<0, 118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119, 184, 106, 21, 195, 178,
                 159, 85, 152>>
             )

    assert {:error, "No version byte"} == CashAddr.decode_payload(<<>>)
    assert {:error, "Invalid reserved bit in version byte"} == CashAddr.decode_payload(<<128>>)
  end
end
