import { SignJWT, importPKCS8 } from "jose";

const GITHUB_API = "https://api.github.com";

// GitHub issues App private keys as PKCS#1 ("BEGIN RSA PRIVATE KEY"), but
// jose/WebCrypto only import PKCS#8. PKCS#8 is the PKCS#1 DER wrapped in a
// PrivateKeyInfo envelope (version + rsaEncryption AlgorithmIdentifier), so
// wrap it ourselves rather than making every installer openssl-convert the
// key they downloaded.
function pkcs1PemToPkcs8Pem(pem: string): string {
  const base64 = pem.replace(/-----(BEGIN|END) RSA PRIVATE KEY-----/g, "").replace(/\s/g, "");
  const pkcs1 = Uint8Array.from(atob(base64), (c) => c.codePointAt(0) ?? 0);

  const derLength = (length: number): number[] => {
    if (length < 0x80) return [length];
    const bytes: number[] = [];
    for (let remaining = length; remaining > 0; remaining >>= 8) bytes.unshift(remaining & 0xff);
    return [0x80 | bytes.length, ...bytes];
  };

  const version = [0x02, 0x01, 0x00];
  const rsaEncryptionAlgId = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
  ];
  const octetString = [0x04, ...derLength(pkcs1.length)];
  const contentLength = version.length + rsaEncryptionAlgId.length + octetString.length + pkcs1.length;
  const pkcs8 = new Uint8Array([
    0x30, ...derLength(contentLength),
    ...version, ...rsaEncryptionAlgId, ...octetString, ...pkcs1,
  ]);

  let binary = "";
  for (const byte of pkcs8) binary += String.fromCodePoint(byte);
  return `-----BEGIN PRIVATE KEY-----\n${btoa(binary)}\n-----END PRIVATE KEY-----`;
}

export async function createAppJwt(appId: string, privateKeyPem: string): Promise<string> {
  const pem = privateKeyPem.includes("BEGIN RSA PRIVATE KEY")
    ? pkcs1PemToPkcs8Pem(privateKeyPem)
    : privateKeyPem;
  const privateKey = await importPKCS8(pem, "RS256");
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuedAt(now - 60) // GitHub allows up to 60s of clock drift
    .setExpirationTime(now + 600) // max 10 minutes
    .setIssuer(appId)
    .sign(privateKey);
}

export async function getInstallationToken(appJwt: string, installationId: number): Promise<string> {
  const res = await fetch(`${GITHUB_API}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "gh-attest",
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to mint installation token for ${installationId} (${res.status})`);
  }

  const data = (await res.json()) as { token: string };
  return data.token;
}
