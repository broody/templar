// P0b spike (throwaway), TEST ONLY: a mock get-starknet wallet backed by a FRESH random Stark key
// (generated per call, kept in memory, never printed or written). index.html never loads this file;
// the node test imports it, and the browser test injects it by hand (README, "Testing").
//
// modes:
//   deterministic  - starknet.js signer behaviour: RFC 6979 nonce, same message -> same signature
//   randomized     - extra entropy per signature (a wallet whose signatures are not repeatable)
//   ascii_version  - hashes the domain with version/revision as ASCII '1' (0x31) instead of 1
import { messageHashVariant, toHexFelt } from '../sign-logic.mjs';

const ICON =
  'data:image/svg+xml;base64,' +
  'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHJlY3Qgd2lkdGg9IjMyIiBoZWlnaHQ9IjMyIiByeD0iNiIgZmlsbD0iIzg4OCIvPjwvc3ZnPg==';

export function createMockWallet(sn, { chainId = '0x534e5f5345504f4c4941', address, mode = 'deterministic' } = {}) {
  const privateKey = sn.ec.starkCurve.utils.randomPrivateKey();
  const fullPublicKey = sn.ec.starkCurve.getPublicKey(privateKey, false);
  const starkKey = sn.ec.starkCurve.getStarkKey(privateKey);
  // A made-up account address derived from the fresh key (no account is deployed).
  const addr = address ?? toHexFelt(sn.ec.starkCurve.poseidonHashMany([BigInt(starkKey), 7n]) % (2n ** 251n - 256n));
  const calls = [];

  const hashFor = (td) =>
    mode === 'ascii_version'
      ? messageHashVariant(sn, td, addr, { versionAscii: true, revisionAscii: true })
      : sn.typedData.getMessageHash(td, addr);

  const swo = {
    id: 'templar-mock',
    name: 'Templar mock wallet (test only)',
    version: '0.0.0',
    icon: ICON,
    async request(call) {
      calls.push(call.type);
      switch (call.type) {
        case 'wallet_requestAccounts':
          return [addr];
        case 'wallet_getPermissions':
          return ['accounts'];
        case 'wallet_requestChainId':
          return chainId;
        case 'wallet_signTypedData': {
          const h = hashFor(call.params);
          const sig = sn.ec.starkCurve.sign(h, privateKey, mode === 'randomized' ? { extraEntropy: true } : undefined);
          return [toHexFelt(sig.r), toHexFelt(sig.s)];
        }
        default:
          throw { code: 163, message: `mock wallet: unsupported ${call.type}` };
      }
    },
    on() {},
    off() {},
  };

  // Stand-in for a single-Stark-key account's is_valid_signature.
  const verify = (hash, signature) => {
    if (signature.length !== 2) return false;
    const s = new sn.ec.starkCurve.Signature(BigInt(signature[0]), BigInt(signature[1]));
    return sn.ec.starkCurve.verify(s, toHexFelt(hash), fullPublicKey);
  };

  return { swo, address: addr, starkKey, calls, verify };
}

// A fake JSON-RPC for readOnlyChecks: the mock account's class hash and is_valid_signature.
export function mockRpc(sn, mock, { classHash = '0x1234abcd' } = {}) {
  const sel = toHexFelt(sn.hash.getSelectorFromName('is_valid_signature'));
  return async (method, params) => {
    if (method === 'starknet_chainId') return '0x534e5f5345504f4c4941';
    if (method === 'starknet_getClassHashAt') {
      if (BigInt(params.contract_address) !== BigInt(mock.address)) throw new Error('RPC 20: Contract not found');
      return classHash;
    }
    if (method === 'starknet_call') {
      const { contract_address, entry_point_selector, calldata } = params.request;
      if (BigInt(contract_address) !== BigInt(mock.address)) throw new Error('RPC 20: Contract not found');
      if (BigInt(entry_point_selector) !== BigInt(sel)) throw new Error('RPC 40: Entry point not found');
      const [hash, len, ...sig] = calldata;
      if (Number(BigInt(len)) !== sig.length) throw new Error('RPC 40: bad calldata');
      return [mock.verify(hash, sig) ? '0x56414c4944' : '0x0'];
    }
    throw new Error(`mock rpc: ${method} not supported`);
  };
}
