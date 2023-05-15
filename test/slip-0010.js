import { test } from 'brittle'
import * as slip0010 from '../lib/slip-0010.js'
import { toHex as hex } from '../lib/buf.js'

test('Test vector 1 for ed25519', async function (assert) {
  const seed = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
  const master = await slip0010.master(seed, slip0010.CURVE_ED25519)

  assert.is(hex(master.chainCode), '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb')
  assert.is(hex(master.secretKey), '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7')

  const m0h = await slip0010.child(master.secretKey, master.chainCode, slip0010.HARDENED_OFFSET + 0)
  assert.is(hex(m0h.chainCode), '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69')
  assert.is(hex(m0h.secretKey), '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3')

  const m0h1h = await slip0010.child(m0h.secretKey, m0h.chainCode, slip0010.HARDENED_OFFSET + 1)
  assert.is(hex(m0h1h.chainCode), 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14')
  assert.is(hex(m0h1h.secretKey), 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2')

  const m0h1h2h = await slip0010.child(m0h1h.secretKey, m0h1h.chainCode, slip0010.HARDENED_OFFSET + 2)
  assert.is(hex(m0h1h2h.chainCode), '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c')
  assert.is(hex(m0h1h2h.secretKey), '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9')

  const m0h1h2h2h = await slip0010.child(m0h1h2h.secretKey, m0h1h2h.chainCode, slip0010.HARDENED_OFFSET + 2)
  assert.is(hex(m0h1h2h2h.chainCode), '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc')
  assert.is(hex(m0h1h2h2h.secretKey), '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662')

  const m0h1h2h2h1000000000h = await slip0010.child(m0h1h2h2h.secretKey, m0h1h2h2h.chainCode, slip0010.HARDENED_OFFSET + 1000000000)
  assert.is(hex(m0h1h2h2h1000000000h.chainCode), '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230')
  assert.is(hex(m0h1h2h2h1000000000h.secretKey), '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793')
})

test('Test vector 2 for ed25519', async function (assert) {
  const seed = new Uint8Array([
    255, 252, 249, 246, 243, 240, 237, 234, 231, 228,
    225, 222, 219, 216, 213, 210, 207, 204, 201, 198,
    195, 192, 189, 186, 183, 180, 177, 174, 171, 168,
    165, 162, 159, 156, 153, 150, 147, 144, 141, 138,
    135, 132, 129, 126, 123, 120, 117, 114, 111, 108,
    105, 102, 99, 96, 93, 90, 87, 84, 81, 78, 75, 72, 69, 66
  ])

  const master = await slip0010.master(seed, slip0010.CURVE_ED25519)

  assert.is(hex(master.chainCode), 'ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b')
  assert.is(hex(master.secretKey), '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012')

  const m0h = await slip0010.child(master.secretKey, master.chainCode, slip0010.HARDENED_OFFSET + 0)
  assert.is(hex(m0h.chainCode), '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d')
  assert.is(hex(m0h.secretKey), '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635')

  const m0h2147483647h = await slip0010.child(m0h.secretKey, m0h.chainCode, slip0010.HARDENED_OFFSET + 2147483647)
  assert.is(hex(m0h2147483647h.chainCode), '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f')
  assert.is(hex(m0h2147483647h.secretKey), 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4')

  const m0h2147483647h1h = await slip0010.child(m0h2147483647h.secretKey, m0h2147483647h.chainCode, slip0010.HARDENED_OFFSET + 1)
  assert.is(hex(m0h2147483647h1h.chainCode), '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90')
  assert.is(hex(m0h2147483647h1h.secretKey), '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c')

  const m0h2147483647h1h2147483646h = await slip0010.child(m0h2147483647h1h.secretKey, m0h2147483647h1h.chainCode, slip0010.HARDENED_OFFSET + 2147483646)
  assert.is(hex(m0h2147483647h1h2147483646h.chainCode), '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a')
  assert.is(hex(m0h2147483647h1h2147483646h.secretKey), '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72')

  const m0h2147483647h1h2147483646h2h = await slip0010.child(m0h2147483647h1h2147483646h.secretKey, m0h2147483647h1h2147483646h.chainCode, slip0010.HARDENED_OFFSET + 2)
  assert.is(hex(m0h2147483647h1h2147483646h2h.chainCode), '5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4')
  assert.is(hex(m0h2147483647h1h2147483646h2h.secretKey), '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d')
})

test('Vega Test Vector', async function (assert) {
  const seed = new Uint8Array([
    140, 23, 113, 200, 214, 237, 150, 38, 30, 90, 116,
    86, 67, 138, 209, 234, 39, 182, 61, 163, 89, 188,
    73, 34, 212, 174, 180, 78, 57, 226, 119, 141, 50,
    47, 24, 199, 248, 2, 160, 128, 21, 5, 186, 149,
    77, 74, 169, 87, 74, 126, 104, 104, 72, 162, 111,
    126, 9, 170, 164, 14, 189, 217, 167, 48
  ])

  const master = await slip0010.master(seed, slip0010.CURVE_ED25519)

  assert.is(hex(master.chainCode), '2bd0f0a05d31e16d4e60afcea06301aa83923bb4db34fea726a49ef9912d4dc5')
  assert.is(hex(master.secretKey), '1a56e2438e5309a43ee2152bb0b44deab3f5a6afccd130bd6a3b6fb569103d48')

  const mVegah = await slip0010.child(master.secretKey, master.chainCode, slip0010.HARDENED_OFFSET + 1789)
  assert.is(hex(mVegah.chainCode), 'ba9fbe7f7ed8a4d6b3d8899fe74df073a95b6dbcd9e8b30ca57538cf0a357993')
  assert.is(hex(mVegah.secretKey), '3e323acf112ee1db5c4eef76758941ff60dafabbd2a60ecacef98b310f70bfa8')

  const mVegah0h = await slip0010.child(mVegah.secretKey, mVegah.chainCode, slip0010.HARDENED_OFFSET + 0)
  assert.is(hex(mVegah0h.chainCode), '0da7bc026856ebf3c1921c3d34516606075cd04a35c1b5ca3564e0122b9ceb07')
  assert.is(hex(mVegah0h.secretKey), '8072662c6b1559226cd119616244763a3ed3992f11f7738a66e3a6f04bdafb2e')

  const mVegah0h0h = await slip0010.child(mVegah0h.secretKey, mVegah0h.chainCode, slip0010.HARDENED_OFFSET + 0)
  assert.is(hex(mVegah0h0h.chainCode), '307c8f8616e102d8d620a5cf3b1b296d139d4ba0264fbe85a5be7ea24260c115')
  assert.is(hex(mVegah0h0h.secretKey), '754ed6c0771ee980f7a8f5f8b78735a0d4c75618b5c96f53dbbd5aeaa93345d3')

  const mVegah0h1h = await slip0010.child(mVegah0h.secretKey, mVegah0h.chainCode, slip0010.HARDENED_OFFSET + 1)
  assert.is(hex(mVegah0h1h.chainCode), 'a950f553512beaa525579208727ade5408ed6928c747f4e05d7472e51a31f1d7')
  assert.is(hex(mVegah0h1h.secretKey), '0bfdfb4a04e22d7252a4f24eb9d0f35a82efdc244cb0876d919361e61f6f56a2')

  const mVegah0h2h = await slip0010.child(mVegah0h.secretKey, mVegah0h.chainCode, slip0010.HARDENED_OFFSET + 2)
  assert.is(hex(mVegah0h2h.chainCode), '59f7afb953ac76ed3e4bf51f5dd40ac5d90c53e2b523d338c78de34ff617bda3')
  assert.is(hex(mVegah0h2h.secretKey), 'f740c89e05e714ca81f01701dcfd3e854796a9e746023a50610d6c9b70ebe72a')
})
