import { VegaWallet, HARDENED } from '../lib/vega-wallet.js'
import { test } from 'brittle'

test('Can recreate wallet from seed', async assert => {
  const mnemonic = 'foo bar'

  const expected = await VegaWallet.fromMnemonic(mnemonic)

  const seed = await VegaWallet.deriveSeed(mnemonic)
  const actual = await VegaWallet.fromSeed(seed)

  assert.alike((await expected.keyPair(HARDENED + 1)).pk, (await actual.keyPair(HARDENED + 1)).pk)
})

test('vegawallet-desktop test vector', async assert => {
  const mnemonic = 'swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render'
  const wallet = await VegaWallet.fromMnemonic(mnemonic)

  assert.is('9df682a3c87d90567f260566a9c223ccbbb7529c38340cf163b8fe199dbf0f2e', wallet.id)
})
