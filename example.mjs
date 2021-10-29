import { Wallet } from './dist/wallet.js'
const mnemonic = 'swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render'

const wallet = await Wallet.fromMnemonic(mnemonic)
const kp = await wallet.keyPair(0)

console.log(JSON.stringify(kp))
