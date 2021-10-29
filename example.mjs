import Wallet from './output/wallet.js'
const mnemonic = 'swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render'

const w = await Wallet.fromMnemonic(mnemonic)
const k = await w.keyPair(0)

console.log(Buffer.from(k.pk._pk).toString('hex'))
