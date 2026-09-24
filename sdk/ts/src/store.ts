// Wallet storage (spec §10.3): every record encrypted in the core under the pool's store key,
// bound to its type and key, under an opaque id; a schema version; one lock per chain and pool.
import { call, wasm } from './core.js';
import { fail } from './errors.js';

/** A byte store. Implementations: `MemoryKV` (tests), `IndexedDBKV` (browsers), `FileKV` (Node). */
export interface KV {
  get(id: string): Promise<Uint8Array | undefined>;
  put(id: string, value: Uint8Array): Promise<void>;
  delete(id: string): Promise<void>;
  /** Runs `f` holding an exclusive lock named `name` (across tabs or processes where supported). */
  lock<T>(name: string, f: () => Promise<T>): Promise<T>;
}

export class MemoryKV implements KV {
  private m = new Map<string, Uint8Array>();
  private chain: Promise<unknown> = Promise.resolve();
  async get(id: string) {
    return this.m.get(id);
  }
  async put(id: string, v: Uint8Array) {
    this.m.set(id, v);
  }
  async delete(id: string) {
    this.m.delete(id);
  }
  lock<T>(_name: string, f: () => Promise<T>): Promise<T> {
    const run = this.chain.then(f, f);
    this.chain = run.catch(() => undefined);
    return run;
  }
  /** For tests: the raw stored bytes. */
  raw(): Map<string, Uint8Array> {
    return this.m;
  }
}

/** IndexedDB, with Web Locks for exclusion across tabs. */
export class IndexedDBKV implements KV {
  private db: Promise<IDBDatabase>;
  constructor(name = 'templar') {
    this.db = new Promise((resolve, reject) => {
      const r = indexedDB.open(name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('records');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  private async tx<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest): Promise<T> {
    const db = await this.db;
    return new Promise((resolve, reject) => {
      const req = f(db.transaction('records', mode).objectStore('records'));
      req.onsuccess = () => resolve(req.result as T);
      req.onerror = () => reject(req.error);
    });
  }
  async get(id: string) {
    const v = await this.tx<Uint8Array | undefined>('readonly', (s) => s.get(id));
    return v === undefined ? undefined : new Uint8Array(v);
  }
  async put(id: string, v: Uint8Array) {
    await this.tx('readwrite', (s) => s.put(v, id));
  }
  async delete(id: string) {
    await this.tx('readwrite', (s) => s.delete(id));
  }
  lock<T>(name: string, f: () => Promise<T>): Promise<T> {
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (!locks) fail('no_locks', 'Web Locks are unavailable; two tabs could sync at once');
    return locks.request(`templar:${name}`, f) as Promise<T>;
  }
}

/** A directory of files (Node), with an exclusive lock file. */
export class FileKV implements KV {
  constructor(private dir: string) {}
  private async fs() {
    const fs = await import('node:fs/promises');
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    return fs;
  }
  async get(id: string) {
    const fs = await this.fs();
    try {
      return new Uint8Array(await fs.readFile(`${this.dir}/${id}`));
    } catch {
      return undefined;
    }
  }
  async put(id: string, v: Uint8Array) {
    const fs = await this.fs();
    const tmp = `${this.dir}/.${id}.tmp`;
    await fs.writeFile(tmp, v, { mode: 0o600 });
    await fs.rename(tmp, `${this.dir}/${id}`);
  }
  async delete(id: string) {
    const fs = await this.fs();
    await fs.rm(`${this.dir}/${id}`, { force: true });
  }
  async lock<T>(name: string, f: () => Promise<T>): Promise<T> {
    const fs = await this.fs();
    const path = `${this.dir}/.lock-${name.replace(/[^a-z0-9]/gi, '')}`;
    const h = await fs.open(path, 'wx').catch(() => fail('locked', `another process holds ${path}`));
    try {
      return await f();
    } finally {
      await h.close();
      await fs.rm(path, { force: true });
    }
  }
}

export const SCHEMA = 1;

/** Encrypted, typed records of one wallet in one pool. */
export class WalletStore {
  constructor(
    private kv: KV,
    private seed: Uint8Array,
    private chain: string,
    private pool: string,
  ) {}

  private id(type: string, key: string): string {
    return call(() => wasm.store_record_id(this.seed, this.chain, this.pool, type, key));
  }

  async get<T>(type: string, key: string): Promise<T | undefined> {
    const sealed = await this.kv.get(this.id(type, key));
    if (!sealed) return undefined;
    const bytes = call(() => wasm.store_open(this.seed, this.chain, this.pool, type, key, sealed));
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  }

  async put<T>(type: string, key: string, value: T): Promise<void> {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    await this.kv.put(this.id(type, key), call(() => wasm.store_seal(this.seed, this.chain, this.pool, type, key, bytes)));
  }

  async delete(type: string, key: string): Promise<void> {
    await this.kv.delete(this.id(type, key));
  }

  /** Checks (or writes) the schema version; a newer schema is refused. */
  async open(): Promise<void> {
    const v = await this.get<number>('meta', 'schema');
    if (v === undefined) await this.put('meta', 'schema', SCHEMA);
    else if (v > SCHEMA) fail('store_schema', `store schema ${v} is newer than this SDK's ${SCHEMA}`);
  }

  lock<T>(f: () => Promise<T>): Promise<T> {
    return this.kv.lock(`${this.chain}-${this.pool}`, f);
  }
}
