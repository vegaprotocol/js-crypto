import rust from '@wasm-tool/rollup-plugin-rust'
import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'

export default [
  {
    input: [
      'crate/index.js'
    ],
    output: [
      {
        file: 'lib/crate.js',
        format: 'es'
      }
    ],
    plugins: [
      rust({
        nodejs: true,
        inlineWasm: true,
        verbose: true
      })
    ]
  },
  {
    external: [
      /node_modules/
    ],
    input: [
      'lib/crate.js',
      'lib/bip-0039/mnemonic.js',
      'lib/bip-0039/seed.js',
      'lib/browser-crypto.js',
      'lib/buf.js',
      'lib/crate.js',
      'lib/crypto.js',
      'lib/hd-wallet.js',
      'lib/keypair.js',
      'lib/pow/sha3r24.js',
      'lib/pow.js',
      'lib/slip-0010.js',
      'lib/vega-wallet.js'
    ],
    output: [
      {
        dir: 'cjs',
        format: 'cjs',
        preserveModules: true,
        preserveModulesRoot: 'lib',
        entryFileNames: '[name].cjs'
      }
    ],
    plugins: [
      nodeResolve(),
      commonjs()
    ]
  }
]
