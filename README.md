# `@vegaprotocol/crypto`

> Crypto operations for Vega supporting Node.js and Browsers

## API

Note: All APIs are async. In some cases they will run sync, eg in Node.js
where loading WASM is sync, or where crypto routines are sync, but everything
is kept async as a lowest common denominator between browser APIs and future
hardware wallet support.

`const wallet = await Wallet.fromMnemonic(mnemonic)`

Generate a new `Wallet` from a BIP-0032 mnemonic. Note that the mnemonic
is not validated before key derivation.

`const kp = await wallet.keyPair(index)`

Generate a new key pair at `index`, under the Vega specific subtree.

`const sig = await kp.sign(msg)`

Sign `msg` with key pair `kp`.

`const isValid = await kp.verify(sig, msg)`

Verify `sig` is valid for `msg` under key pair `kp`.

### Spec

BIP-0032 based mnemonic with SLIP-0010 derivation of Ed25519 keys.

```
fun BIP39-Seed (Mnemonic, WalletPassword = "") -> Seed
  H = HMAC-SHA-512
  Salt = "mnemonic" || WalletPassword
  Password = mnemonic
  Iterations = 2048
  KeyBytes = 64

  Seed = PBKDF2(H, Salt, Password, Iterations, KeyBytes)


fun MasterNode (Seed) -> MasterChainCode, MasterKey
  Key = "ed25519 seed"
  Data = seed
  I = HMAC-SHA-512(Key, Data)

  MasterKey = I[0:32]
  MasterChainCode = I[32:64]


fun HardenedChildNode (ParentChainCode, ParentKey, Index) -> ChildChainCode, ChildKey
  Key = ParentChainCode
  Data = 0x00 || ParentKey || U32BE(0x8000_0000 | Index)
  I = HMAC-SHA-512(Key, Data)

  ChildKey = I[0:32]
  ChildChainCode = I[32:64]


fun HDWallet (Mnemonic) -> Derive
  Seed = BIP32-Seed(Mnemonic)
  // Path: "m"
  MasterChainCode, MasterKey = MasterNode(Seed)

  // Vega magic
  VEGA = 1789
  // Path: "m/'MAGIC"
  VegaChainCode, VegaKey = HardenedChildNode(MasterChainCode, MasterKey, VEGA)

  // Default sub node
  ChainCode, Key = HardenedChildNode(VegaChainCode, VegaKey, 0)

  // Path: "m/'VEGA/'0/Index"
  fun Derive (Index) -> PrivateKey
    _, PrivateKey = HardenedChildNode(ChainCode, Key, Index)
```

EdDSA with Ed25519 and SHA-512 over a SHA-3/256 digest.

```
fun Sign (Message, PrivateKey) -> Signature
  Digest = SHA3-256(Message)

  Curve = Ed25519
  H = SHA-512
  Key = PrivateKey
  Data = Digest
  Nonce = H( H(PrivateKey)[32:64] || Digest ) // RFC

  Signature = EdDSA-Sign(Curve, H, Key, Data, Nonce)

fun Verify (Signature, Message, PublicKey) -> {T, F}
  Digest = SHA3-256(Message)

  Curve = Ed25519
  H = SHA-512
  Data = Digest

  return EdDSA-Verify(Curve, H, PublicKey, Data, Signature)

```

### Test Vectors

#### Vector 1

Mnemonic: swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render

Seed: `8c1771c8d6ed96261e5a7456438ad1ea27b63da359bc4922d4aeb44e39e2778d322f18c7f802a0801505ba954d4aa9574a7e686848a26f7e09aaa40ebdd9a730`

Path: `m`
  Key: `1a56e2438e5309a43ee2152bb0b44deab3f5a6afccd130bd6a3b6fb569103d48`
  Chain Code: `2bd0f0a05d31e16d4e60afcea06301aa83923bb4db34fea726a49ef9912d4dc5`
  Private Key: `1a56e2438e5309a43ee2152bb0b44deab3f5a6afccd130bd6a3b6fb569103d48b5e1866efa91462b717d40c6ad4de6ef02e4d060115fdddab54f11964a7a8d11`
  Public Key: `b5e1866efa91462b717d40c6ad4de6ef02e4d060115fdddab54f11964a7a8d11`

Path: `m/'VEGA`
  Key: `3e323acf112ee1db5c4eef76758941ff60dafabbd2a60ecacef98b310f70bfa8`
  Chain Code: `ba9fbe7f7ed8a4d6b3d8899fe74df073a95b6dbcd9e8b30ca57538cf0a357993`
  Private Key: `3e323acf112ee1db5c4eef76758941ff60dafabbd2a60ecacef98b310f70bfa89df682a3c87d90567f260566a9c223ccbbb7529c38340cf163b8fe199dbf0f2e`
  Public Key: `9df682a3c87d90567f260566a9c223ccbbb7529c38340cf163b8fe199dbf0f2e`

Path: `m/'VEGA/'0`
  Key: `8072662c6b1559226cd119616244763a3ed3992f11f7738a66e3a6f04bdafb2e`
  Chain Code: `0da7bc026856ebf3c1921c3d34516606075cd04a35c1b5ca3564e0122b9ceb07`
  Private Key: `8072662c6b1559226cd119616244763a3ed3992f11f7738a66e3a6f04bdafb2e28de55a105367539135f79581590c2316ce1571747b42ace13071f452f4ed590`
  Public Key: `28de55a105367539135f79581590c2316ce1571747b42ace13071f452f4ed590`

Path: `m/'VEGA/'0/'0`
  Key: `754ed6c0771ee980f7a8f5f8b78735a0d4c75618b5c96f53dbbd5aeaa93345d3`
  Chain Code: `307c8f8616e102d8d620a5cf3b1b296d139d4ba0264fbe85a5be7ea24260c115`
  Private Key: `754ed6c0771ee980f7a8f5f8b78735a0d4c75618b5c96f53dbbd5aeaa93345d36b3e197785a6f7614f52c07a0e3e7807a4dfbde3db828ed6f716261269974772`
  Public Key: `6b3e197785a6f7614f52c07a0e3e7807a4dfbde3db828ed6f716261269974772`

Path: `m/'VEGA/'0/'1`
  Key: `0bfdfb4a04e22d7252a4f24eb9d0f35a82efdc244cb0876d919361e61f6f56a2`
  Chain Code: `a950f553512beaa525579208727ade5408ed6928c747f4e05d7472e51a31f1d7`
  Private Key: `0bfdfb4a04e22d7252a4f24eb9d0f35a82efdc244cb0876d919361e61f6f56a2b5fd9d3c4ad553cb3196303b6e6df7f484cf7f5331a572a45031239fd71ad8a0`
  Public Key: `b5fd9d3c4ad553cb3196303b6e6df7f484cf7f5331a572a45031239fd71ad8a0`

Path: `m/'VEGA/'0/'2`
  Key: `f740c89e05e714ca81f01701dcfd3e854796a9e746023a50610d6c9b70ebe72a`
  Chain Code: `59f7afb953ac76ed3e4bf51f5dd40ac5d90c53e2b523d338c78de34ff617bda3`
  Private Key: `f740c89e05e714ca81f01701dcfd3e854796a9e746023a50610d6c9b70ebe72a988eae323a07f12363c17025c23ee58ea32ac3912398e16bb0b56969f57adc52`
  Public Key: `988eae323a07f12363c17025c23ee58ea32ac3912398e16bb0b56969f57adc52`

## License

[MIT](LICENSE)
