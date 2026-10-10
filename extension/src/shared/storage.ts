// Thin, typed wrappers over chrome.storage. Settings live in sync storage (so
// they follow the user across machines); the connection token and the
// notification history live in local storage (token must never sync to other
// devices; history can be large).

import { DEFAULT_SETTINGS, type Settings, type HeimdallNotification } from './types';

const TOKEN_KEY = 'heimdall.token';
const EMAIL_KEY = 'heimdall.email';
const SETTINGS_KEY = 'heimdall.settings';
const NOTIFS_KEY = 'heimdall.notifications';
const MAX_NOTIFS = 100;

export async function getToken(): Promise<string | null> {
  const o = await chrome.storage.local.get(TOKEN_KEY);
  return (o[TOKEN_KEY] as string | undefined) ?? null;
}
export async function setToken(token: string): Promise<void> {
  await chrome.storage.local.set({ [TOKEN_KEY]: token });
}
export async function clearToken(): Promise<void> {
  await chrome.storage.local.remove([TOKEN_KEY, EMAIL_KEY]);
}

export async function getCachedEmail(): Promise<string | null> {
  const o = await chrome.storage.local.get(EMAIL_KEY);
  return (o[EMAIL_KEY] as string | undefined) ?? null;
}
export async function setCachedEmail(email: string | null): Promise<void> {
  await chrome.storage.local.set({ [EMAIL_KEY]: email ?? '' });
}

export async function getSettings(): Promise<Settings> {
  const o = await chrome.storage.sync.get(SETTINGS_KEY);
  return { ...DEFAULT_SETTINGS, ...((o[SETTINGS_KEY] as Partial<Settings> | undefined) ?? {}) };
}
export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.sync.set({ [SETTINGS_KEY]: next });
  return next;
}

export async function getNotifications(): Promise<HeimdallNotification[]> {
  const o = await chrome.storage.local.get(NOTIFS_KEY);
  return (o[NOTIFS_KEY] as HeimdallNotification[] | undefined) ?? [];
}
export async function saveNotifications(list: HeimdallNotification[]): Promise<void> {
  await chrome.storage.local.set({ [NOTIFS_KEY]: list.slice(0, MAX_NOTIFS) });
}
