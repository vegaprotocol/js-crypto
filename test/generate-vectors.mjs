import * as hd from '../dist/hd.js'
import { KeyPair } from '../dist/keypair.js'

const mnemonic = 'swing ceiling chaos green put insane ripple desk match tip melt usual shrug turkey renew icon parade veteran lens govern path rough page render'
console.log('mnemonic:', mnemonic)
console.log('')

const seed = await hd.bip39Seed(mnemonic)
console.log('seed:', seed.toString('hex'))
console.log('')

const { masterKey, masterChainCode } = await hd.masterNode(seed)
console.log('Path: "m"')
console.log('  Key:', masterKey.toString('hex'))
console.log('  Chain Code:', masterChainCode.toString('hex'))
const mkp = await KeyPair.fromSeed(0, masterKey)
console.log('  Private Key:', mkp.sk.toString())
console.log('  Public Key:', mkp.pk.toString())
console.log('')

const {
  childChainCode: vegaChainCode,
  childKey: vegaKey
} = await hd.hardenedChildNode(masterChainCode, masterKey, hd.VEGA_COINTYPE)
console.log('Path: "m/\'VEGA"')
console.log('  Key:', vegaKey.toString('hex'))
console.log('  Chain Code:', vegaChainCode.toString('hex'))
const vkp = await KeyPair.fromSeed(hd.VEGA_COINTYPE, vegaKey)
console.log('  Private Key:', vkp.sk.toString())
console.log('  Public Key:', vkp.pk.toString())
console.log('')

const {
  childChainCode,
  childKey
} = await hd.hardenedChildNode(vegaChainCode, vegaKey, 0)
console.log('Path: "m/\'VEGA/\'0"')
console.log('  Key:', childKey.toString('hex'))
console.log('  Chain Code:', childChainCode.toString('hex'))
const ckp = await KeyPair.fromSeed(0, childKey)
console.log('  Private Key:', ckp.sk.toString())
console.log('  Public Key:', ckp.pk.toString())
console.log('')

for (let i = 0; i < 3; i++) {
  const {
    childChainCode: cc,
    childKey: ck
  } = await hd.hardenedChildNode(childChainCode, childKey, i)
  console.log(`Path: "m/'VEGA/'0/'${i}"`)
  console.log('  Key:', ck.toString('hex'))
  console.log('  Chain Code:', cc.toString('hex'))
  const cckp = await KeyPair.fromSeed(i, ck)
  console.log('  Private Key:', cckp.sk.toString())
  console.log('  Public Key:', cckp.pk.toString())
  console.log('')
}
