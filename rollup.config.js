import rust from '@wasm-tool/rollup-plugin-rust'
import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'

export default {
  input: [
    'lib/buf.js',
    'lib/crypto.js',
    'lib/browser-crypto.js',
    'lib/bip-0039.js',
    'lib/slip-0010.js',
    'lib/keypair.js',
    'lib/hd-wallet.js',
    'lib/wallet.js'
  ],
  output: [
    {
      dir: 'esm',
      format: 'es'
    },
    {
      dir: 'cjs',
      format: 'cjs'
    }
  ],
  plugins: [commonjs(), nodeResolve(), rust({ inlineWasm: true })]
}
