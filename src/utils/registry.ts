import type * as httpsType from 'node:https';
import type { IncomingMessage, ClientRequest, RequestOptions } from 'node:http';

export interface RegistryData {
  created: string;
  latestScripts: Record<string, string>;
  name: string;
}

export type RegistryResult =
  | { status: 'ok'; data: RegistryData }
  | { status: 'not-found' }
  | { status: 'error'; reason: string };

export type RegistryFetchFn = (
  url: string,
  options: RequestOptions,
  callback: (res: IncomingMessage) => void,
) => ClientRequest;

const REGISTRY_BASE = 'https://registry.npmjs.org/';
const MAX_BODY_BYTES = 25 * 1024 * 1024;

let httpsModule: typeof httpsType | null = null;

async function getRealFetch(): Promise<RegistryFetchFn> {
  if (!httpsModule) {
    httpsModule = await import('node:https');
  }
  return (url, options, cb) => httpsModule!.get(url, options, cb);
}

export async function fetchRegistry(
  packageName: string,
  timeoutMs = 5_000,
  fetchFn?: RegistryFetchFn,
): Promise<RegistryResult> {
  const activeFetch = fetchFn ?? (await getRealFetch());
  const encoded = encodeURIComponent(packageName);
  const url = `${REGISTRY_BASE}${encoded}`;

  return new Promise<RegistryResult>((resolve) => {
    let settled = false;

    const done = (result: RegistryResult): void => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
      done({ status: 'error', reason: 'Request timed out' });
    }, timeoutMs);

    let req: ClientRequest | undefined;

    try {
      req = activeFetch(url, { signal: controller.signal }, (res) => {
        clearTimeout(timer);

        if (res.statusCode === 404) {
          res.resume();
          done({ status: 'not-found' });
          return;
        }

        if (res.statusCode !== 200) {
          res.resume();
          done({ status: 'error', reason: `HTTP ${res.statusCode ?? 'unknown'}` });
          return;
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_BODY_BYTES) {
            res.destroy();
            done({ status: 'error', reason: 'Response too large' });
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          try {
            const body = Buffer.concat(chunks).toString('utf8');
            const json = JSON.parse(body) as Record<string, unknown>;
            done({ status: 'ok', data: parseRegistryJson(json) });
          } catch {
            done({ status: 'error', reason: 'Invalid JSON response' });
          }
        });

        res.on('error', (err: Error) => {
          done({ status: 'error', reason: err.message });
        });
      });
    } catch (err: unknown) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      done({ status: 'error', reason: msg });
      return;
    }

    req.on('error', (err: Error) => {
      clearTimeout(timer);
      if (!settled) {
        done({ status: 'error', reason: err.message });
      }
    });
  });
}

function parseRegistryJson(json: Record<string, unknown>): RegistryData {
  const name = typeof json['name'] === 'string' ? json['name'] : '';

  const time = json['time'];
  const created =
    time !== null && typeof time === 'object' && 'created' in time && typeof (time as Record<string, unknown>)['created'] === 'string'
      ? (time as Record<string, string>)['created']!
      : '';

  const distTags = json['dist-tags'];
  const latestVersion =
    distTags !== null && typeof distTags === 'object' && 'latest' in distTags
      ? (distTags as Record<string, string>)['latest']
      : undefined;

  let latestScripts: Record<string, string> = {};
  if (latestVersion) {
    const versions = json['versions'];
    if (versions !== null && typeof versions === 'object' && latestVersion in (versions as object)) {
      const latestPkg = (versions as Record<string, unknown>)[latestVersion];
      if (latestPkg !== null && typeof latestPkg === 'object' && 'scripts' in latestPkg) {
        const scripts = (latestPkg as Record<string, unknown>)['scripts'];
        if (scripts !== null && typeof scripts === 'object') {
          latestScripts = scripts as Record<string, string>;
        }
      }
    }
  }

  return { name, created, latestScripts };
}
