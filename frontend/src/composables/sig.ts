export const str2ab = (str: string) => {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

export const ab2str = (buf: ArrayBuffer) => {
  return String.fromCharCode.apply(null, Array.from(new Uint8Array(buf)));
}

const xorBuffer = (a: ArrayBuffer, key: ArrayBuffer) => {
  const a8 = new Uint8Array(a)
  const key8 = new Uint8Array(key)
  for (let i = 0; i < a.byteLength; i += 1)
    a8[i] ^= key8[i]
}

const getXorKey = async (password: string, length: number) => {
  const baseKey = await crypto.subtle.importKey(
    "raw", (new TextEncoder()).encode(password),
    "PBKDF2", false, ["deriveBits"]
  )
  // length for PBKDF2 key derivation must be a multiple of 8 bits
  const key = await window.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: str2ab("\x8doSl\x13h\x15B2\x16\x8d.\xac-O\x96"),
      iterations: 1926,
      hash: "SHA-256",
    }, baseKey, length * 8
  );
  return key.slice(0, length)
}

export const importPEMPrivKey = async (privkey: string, password: string) => {
  privkey = privkey.trim()
  const pemHeader = '-----BEGIN PRIVATE KEY-----\n';
  const pemFooter = '\n-----END PRIVATE KEY-----';

  // fetch the part of the PEM string between header and footer
  const pemContents = privkey.substring(pemHeader.length, privkey.length - pemFooter.length);
  // base64 decode the string to get the binary data
  const binaryDerString = atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);
  // decrypt using password
  xorBuffer(binaryDer, await getXorKey(password, binaryDer.byteLength))

  return crypto.subtle.importKey(
    'pkcs8', binaryDer, {
    name: 'ECDSA',
    namedCurve: 'P-256',
  }, true, ['sign']
  );
}

export const getPubKey = async (privKey: CryptoKey) => {
  const jwkPrivate = await crypto.subtle.exportKey('jwk', privKey);
  delete jwkPrivate.d;
  jwkPrivate.key_ops = ['verify'];
  return crypto.subtle.importKey(
    'jwk', jwkPrivate, {
    name: 'ECDSA',
    namedCurve: 'P-256'
  }, true, ['verify']
  );
}

const wrapPEM = (raw: string) => {
  return raw.replace(/(.{64})/g, "$1\n")
}

export const exportPEMPubKey = async (pubKey: CryptoKey) => {
  const exported = await crypto.subtle.exportKey('spki', pubKey);
  const exportedAsBase64 = btoa(ab2str(exported));
  return `-----BEGIN PUBLIC KEY-----\n${wrapPEM(exportedAsBase64)}\n-----END PUBLIC KEY-----`;
}

export const exportPEMPrivKey = async (privKey: CryptoKey, password: string) => {
  const binaryDer = await crypto.subtle.exportKey("pkcs8", privKey)
  xorBuffer(binaryDer, await getXorKey(password, binaryDer.byteLength))
  const binaryDerString = btoa(ab2str(binaryDer))
  return `-----BEGIN PRIVATE KEY-----\n${wrapPEM(binaryDerString)}\n-----END PRIVATE KEY-----`
}

export const generateSignature = async (privkey: CryptoKey, data: string) => {
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    }, privkey, str2ab(data)
  );
  return btoa(ab2str(signature));
}

export const generateKeyPair = async () => (
  crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, ["sign"]
  )
)