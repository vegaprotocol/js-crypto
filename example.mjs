import { VegaWallet, HARDENED } from '@vegaprotocol/crypto'
const mnemonic = 'swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render'

;(async () => {
  const wallet = await VegaWallet.fromMnemonic(mnemonic)
  const kp = await wallet.keyPair(HARDENED + 0)

  console.log(JSON.stringify(kp))
})()
