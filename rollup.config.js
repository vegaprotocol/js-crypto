import rust from '@wasm-tool/rollup-plugin-rust'
import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'

export default {
  input: [
    'lib/crypto.mjs',
    'lib/browser-crypto.mjs',
    'lib/bip-0039.mjs',
    'lib/slip-0010.mjs',
    'lib/keypair.mjs',
    'lib/hd-wallet.mjs',
    'lib/wallet.mjs'
  ],
  output: {
    dir: 'dist',
    format: 'es'
  },
  plugins: [commonjs(), nodeResolve(), rust({ inlineWasm: true })]
}
