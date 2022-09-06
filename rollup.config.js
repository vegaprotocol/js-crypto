import rust from '@wasm-tool/rollup-plugin-rust'

export default {
  input: 'crate/index.js',
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
}
