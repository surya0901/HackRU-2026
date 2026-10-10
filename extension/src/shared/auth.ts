// Account auth for the Chrome extension — the browser sibling of the VS Code
// extension's AuthManager. Same backend handshake: open the Clerk-protected
// /connect/extension page, which mints a the existing connection token connection token and
// hands it back. We use chrome.identity.launchWebAuthFlow so the redirect lands
// on the extension's own https://<id>.chromiumapp.org/ callback — no need to
// know the extension id ahead of time. A paste-the-code fallback covers locked-
// down environments.

import { getToken, setToken, clearToken, setCachedEmail, getSettings } from './storage';

const TOKEN_PREFIX = 'sk_sentinel_';

export async function dashboardUrl(): Promise<string> {
  const s = await getSettings();
  return s.dashboardUrl.replace(/\/+$/, '');
}

export async function isSignedIn(): Promise<boolean> {
  return (await getToken()) !== null;
}

export function looksLikeToken(value: string): boolean {
  return value.trim().startsWith(TOKEN_PREFIX);
}

/** Interactive sign-in via the dashboard. Returns the raw token on success. */
export async function signInInteractive(): Promise<string> {
  const base = await dashboardUrl();
  const redirectUri = chrome.identity.getRedirectURL(); // https://<id>.chromiumapp.org/
  const state = crypto.randomUUID();
  const authUrl =
    `${base}/connect/extension` +
    `?state=${encodeURIComponent(state)}` +
    `&redirect=${encodeURIComponent(redirectUri)}`;

  const redirect = await chrome.identity.launchWebAuthFlow({ url: authUrl, interactive: true });
  if (!redirect) throw new Error('Sign-in was cancelled.');

  const url = new URL(redirect);
  // Token comes back either in the query or the fragment, depending on redirect.
  const params = new URLSearchParams(url.search || url.hash.replace(/^#/, ''));
  const token = params.get('token');
  const returnedState = params.get('state');
  if (!token) throw new Error('No connection token returned from the dashboard.');
  if (returnedState && returnedState !== state) throw new Error('Sign-in could not be verified (state mismatch).');
  if (!looksLikeToken(token)) throw new Error('The returned value is not a valid connection token.');

  await setToken(token);
  return token;
}

/** Fallback: user pastes the connection code from the dashboard. */
export async function signInWithCode(token: string): Promise<void> {
  const t = token.trim();
  if (!looksLikeToken(t)) throw new Error('That does not look like a valid connection code.');
  await setToken(t);
}

export async function signOut(): Promise<void> {
  await clearToken();
  await setCachedEmail(null);
}
