# `@vegaprotocol/crypto`

> ⚠️ Under active development ⚠️

> Crypto operations for Vega supporting Node.js and Browsers

## Usage

This module supports both CommonJS and ES Modules:

```js
const { VegaWallet, HARDENED } = require('@vegaprotocol/crypto')

VegaWallet.fromMnemonic('...').then(async wallet => {
  const keys = await wallet.keyPair(HARDENED + 0)

  const msg = Buffer.from('Hello world!')
  const signature = await keys.sign(msg)
})
```

```js
import { VegaWallet, HARDENED } from '@vegaprotocol/crypto'

const wallet = await VegaWallet.fromMnemonic('...')
const keys = await wallet.keyPair(HARDENED + 0)

const msg = Buffer.from('Hello world!')
const signature = await keys.sign(msg)
```

## API

Note: All APIs are async. In some cases they will run sync, eg in Node.js
where loading WASM is sync, or where crypto routines are sync, but everything
is kept async as a lowest common denominator between browser APIs and future
hardware wallet support.

### `const wallet = await VegaWallet.fromMnemonic(mnemonic)`

Derive a new SLIP-10 `VegaWallet` from a BIP-0039 mnemonic. Note that the
mnemonic is not validated before key derivation.

### `const seed = await VegaWallet.deriveSeed(mnemonic)`

Derive a `seed` from a BIP-0039 mnemonic. In combination with
`VegaWallet.fromSeed` this is equivalent to `VegaWallet.fromMnemonic`.
Note that the mnemonic is not validated before key derivation.

### `const wallet = await VegaWallet.fromSeed(seed)`

Derive a new SLIP-10 `VegaWallet` from a `seed`.

### `const { name, version } = wallet.algorithm`

This contains `name` and `version` detailing the version used by the
instantiated wallet. Note if this changes in the future other "builder"
methods will be exposed to derive newer versions.

### `const kp = await wallet.keyPair(index)`

Generate a new key pair at `index`, under the Vega specific subtree.

### `const sig = await kp.sign(msg, [chainId])`

Sign `msg` with key pair `kp` for optional `chainId`.

### `const isValid = await kp.verify(sig, msg, [chainId])`

Verify `sig` is valid for `msg` under key pair `kp` for optional `chainId`.

## Spec

See [algorithm.md](docs/algorithm.md) and [test-vectors](docs/test-vectors.md).

## License

[MIT](LICENSE)
