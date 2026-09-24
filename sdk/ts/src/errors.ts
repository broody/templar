/** An error from the SDK or its core, with a stable machine-readable code. */
export class TemplarError extends Error {
  constructor(public readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = 'TemplarError';
  }
}

/** Turns a core error (thrown as a JSON `{code, message}` string) into a `TemplarError`. */
export function coreError(e: unknown): TemplarError {
  if (typeof e === 'string') {
    try {
      const v = JSON.parse(e) as { code?: string; message?: string };
      if (v && typeof v.code === 'string') return new TemplarError(v.code, v.message ?? '');
    } catch {
      /* not JSON */
    }
    return new TemplarError('core', e);
  }
  if (e instanceof TemplarError) return e;
  return new TemplarError('core', e instanceof Error ? e.message : String(e));
}

export function fail(code: string, message: string): never {
  throw new TemplarError(code, message);
}
