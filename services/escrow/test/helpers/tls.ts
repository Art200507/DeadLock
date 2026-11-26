/**
 * Test-only TLS: a throwaway CA and server certificates, generated in memory per test run with
 * @peculiar/x509 over WebCrypto. Nothing is written to disk and nothing here is a real key.
 */
import "reflect-metadata";
import { webcrypto } from "node:crypto";
import * as https from "node:https";
import type { AddressInfo } from "node:net";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);
type CryptoKeyPair = webcrypto.CryptoKeyPair;
const alg = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" } as const;

export interface TestCa {
  certPem: string;
  keys: CryptoKeyPair;
  cert: x509.X509Certificate;
}

const pem = (label: string, der: ArrayBuffer) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END ${label}-----\n`;

const serial = () => Buffer.from(webcrypto.getRandomValues(new Uint8Array(8))).toString("hex").replace(/^[89a-f]/, "1");

export async function testCa(name = "Condition Lock Test CA"): Promise<TestCa> {
  const keys = (await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: `CN=${name}`,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: alg,
    keys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { certPem: cert.toString("pem"), keys, cert };
}

export async function serverCert(ca: TestCa, hostnames: string[]): Promise<{ certPem: string; keyPem: string }> {
  const keys = (await webcrypto.subtle.generateKey(alg, true, ["sign", "verify"])) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: `CN=${hostnames[0]}`,
    issuer: ca.cert.subject,
    notBefore: new Date(Date.now() - 3_600_000),
    notAfter: new Date(Date.now() + 86_400_000),
    signingAlgorithm: alg,
    publicKey: keys.publicKey,
    signingKey: ca.keys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension(hostnames.map((h) => ({ type: "dns" as const, value: h }))),
    ],
  });
  const keyPem = pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  return { certPem: cert.toString("pem"), keyPem };
}

export interface TestHttpsServer {
  port: number;
  close(): Promise<void>;
}

export async function startHttps(
  tlsCert: { certPem: string; keyPem: string },
  handler: (req: import("node:http").IncomingMessage, body: string) => { status?: number; json: unknown; headers?: Record<string, string> },
): Promise<TestHttpsServer> {
  const server = https.createServer({ cert: tlsCert.certPem, key: tlsCert.keyPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (d: Buffer) => chunks.push(d));
    req.on("end", () => {
      const out = handler(req, Buffer.concat(chunks).toString("utf8"));
      res.writeHead(out.status ?? 200, { "content-type": "application/json", ...(out.headers ?? {}) });
      res.end(JSON.stringify(out.json));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: (server.address() as AddressInfo).port,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}
