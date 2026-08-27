// FIXTURE — deliberately vulnerable. Must be flagged by modules 01, 03 and 04 rules.
import AsyncStorage from '@react-native-async-storage/async-storage';

export async function save(accessToken: string, refreshToken: string) {
  await AsyncStorage.setItem('authToken', accessToken);
  await AsyncStorage.setItem('refreshToken', refreshToken);
  localStorage.setItem('sessionToken', accessToken);
}

export function client() {
  return fetch('https://api.example.com/v1/x', { rejectUnauthorized: false } as any);
}

export function unsafeEnv() {
  return process.env.EXPO_PUBLIC_STRIPE_SECRET_KEY;
}

export function handleLink(url: string, navigation: any) {
  const parsed = new URL(url);
  if (url.startsWith('https://links.example.com')) {
    navigation.navigate('Home');
  }
  return parsed;
}
