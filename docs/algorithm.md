# Algorithm

Below is the cryptographic algorithms used by Vega vesion 1 (`vega/ed25519`) in pseudo code.

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
  // Path: "m/'VEGA"
  VegaChainCode, VegaKey = HardenedChildNode(MasterChainCode, MasterKey, VEGA)

  // Default sub node
  ChainCode, Key = HardenedChildNode(VegaChainCode, VegaKey, 0)

  // Path: "m/'VEGA/'0/Index"
  fun Derive (Index) -> PrivateKey
    _, PrivateKey = HardenedChildNode(ChainCode, Key, Index)
```

EdDSA with Ed25519 and SHA-512 over a SHA-3/256 digest.

```
fun Sign (Message, PrivateKey, ChainID) -> Signature
  Digest = SHA3-256(ChainID || 0x00 || Message)

  Curve = Ed25519
  H = SHA-512
  Key = PrivateKey
  Data = Digest
  Nonce = H( H(PrivateKey)[32:64] || Digest ) // RFC

  Signature = EdDSA-Sign(Curve, H, Key, Data, Nonce)

fun Verify (Signature, Message, PublicKey, ChainID) -> {T, F}
  Digest = SHA3-256(ChainID  || 0x00 || Message)

  Curve = Ed25519
  H = SHA-512
  Data = Digest

  return EdDSA-Verify(Curve, H, PublicKey, Data, Signature)

```
