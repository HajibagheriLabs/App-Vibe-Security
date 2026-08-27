// FIXTURE — remediated counterpart. Must produce ZERO findings.
import * as Keychain from 'react-native-keychain';

const SERVICE = 'com.example.app.auth';
const ALLOWED_HOSTS = new Set(['links.example.com']);
const ROUTES = new Map([['order-detail', /^[0-9a-f-]{36}$/]]);

let accessToken: string | null = null;

export async function save(at: string, refresh: string) {
  accessToken = at;
  await Keychain.setGenericPassword('refresh', refresh, {
    service: SERVICE,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
  });
}

export function client() {
  return fetch('https://api.example.com/v1/x', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

export function resolveDeepLink(raw: string) {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { return null; }
  if (parsed.protocol !== 'https:') return null;
  if (!ALLOWED_HOSTS.has(parsed.hostname)) return null;
  if (parsed.username || parsed.password) return null;
  const key = parsed.pathname.split('/').filter(Boolean)[0];
  const schema = key ? ROUTES.get(key) : undefined;
  if (!schema) return null;
  const id = parsed.searchParams.get('orderId') ?? '';
  if (!schema.test(id)) return null;
  return { route: key, params: { orderId: id } };
}
