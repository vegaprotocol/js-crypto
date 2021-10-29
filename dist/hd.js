import { pbkdf2Sha512, hmacSha512 } from './crypto.js';
import { s as string, c as concat, u as u32be, a as u8 } from './buf-ba61d454.js';
import 'crypto';

const BIP39_SALT_PREFIX = string('mnemonic');
const BIP39_ITERATIONS = 2048;
const BIP39_KEYBYTES = 64;

async function bip39Seed (mnemonic, walletPassword = '') {
  const salt = concat(BIP39_SALT_PREFIX, string(walletPassword));
  const password = string(mnemonic);

  return pbkdf2Sha512(
    password,
    salt,
    BIP39_ITERATIONS,
    BIP39_KEYBYTES
  )
}

const SLIP10_ED25519_SEED = string('ed25519 seed');
const SLIP44_VEGA_COINTYPE = 1789;
const SLIP10_HARDENED = 0x8000_0000;

async function masterNode (seed) {
  const key = SLIP10_ED25519_SEED;
  const data = string(seed);
  const I = await hmacSha512(key, data);

  return {
    masterKey: I.subarray(0, 32),
    masterChainCode: I.subarray(32, 64)
  }
}

async function hardenedChildNode (parentChainCode, parentKey, index) {
  const key = parentChainCode;
  const data = concat(u8(0x00), string(parentKey), u32be((SLIP10_HARDENED | index) >>> 0));
  const I = await hmacSha512(key, data);

  return {
    childKey: I.subarray(0, 32),
    childChainCode: I.subarray(32, 64)
  }
}

async function wallet (mnemonic) {
  const seed = await bip39Seed(mnemonic);

  const { masterKey, masterChainCode } = await masterNode(seed);

  const {
    childChainCode: vegaChainCode,
    childKey: vegaKey
  } = await hardenedChildNode(masterChainCode, masterKey, SLIP44_VEGA_COINTYPE);

  const {
    childChainCode,
    childKey
  } = await hardenedChildNode(vegaChainCode, vegaKey, 0);

  return async function derive (index) {
    const {
      childKey: privateKey
    } = await hardenedChildNode(childChainCode, childKey, index);

    return privateKey
  }
}

export { SLIP44_VEGA_COINTYPE as VEGA_COINTYPE, bip39Seed, wallet as default, hardenedChildNode, masterNode };
