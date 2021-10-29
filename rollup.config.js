import rust from '@wasm-tool/rollup-plugin-rust'
import { nodeResolve } from '@rollup/plugin-node-resolve'

export default {
  input: [
    'lib/crypto.mjs',
    'lib/browser-crypto.mjs',
    'lib/keypair.mjs',
    'lib/hd.mjs',
    'lib/wallet.mjs'
  ],
  output: {
    dir: 'dist',
    format: 'es'
  },
  plugins: [nodeResolve(), rust({ inlineWasm: true })]
}
