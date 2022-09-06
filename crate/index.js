import crate from '../crate/Cargo.toml'

// Start loading the wasm right away and "memoize" promise
export const wasm = crate()
