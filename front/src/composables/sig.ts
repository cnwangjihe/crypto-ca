export function str2ab(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export function ab2str(buf: ArrayBuffer): string {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function importPrivKey(privkey: string): Promise<CryptoKey> {
  privkey = privkey.trim()
  const pemHeader = '-----BEGIN PRIVATE KEY-----\n';
  const pemFooter = '\n-----END PRIVATE KEY-----';

  // fetch the part of the PEM string between header and footer
  const pemContents = privkey.substring(pemHeader.length, privkey.length - pemFooter.length);
  console.log(pemContents);
  // base64 decode the string to get the binary data
  const binaryDerString = atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);
  console.dir(binaryDer)

  return await crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign']
  );
}

export const generateSigature = async (privkey: string, data: string) => {
  console.log(data)
  const key = await importPrivKey(privkey)
  console.log(key)
  const msg = str2ab(data)
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    }, key, msg
  );
  console.log(signature)
  return btoa(ab2str(signature));
}