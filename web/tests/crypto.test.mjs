import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  encryptBytes,
  decryptBytes,
  inspectBytes,
  canonical,
  strictJSON,
  toBase64,
  fromBase64,
  MAX_PLAINTEXT,
  AuthenticationError,
  FormatError,
  AUTHENTICATION_MESSAGE,
} from "../src/crypto.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const archive = JSON.parse(
  await readFile(new URL("../../tests/archive/index.json", import.meta.url)),
);
const phrase = archive.public_regression_passphrase; // Public fixture data, never a real credential.
const encode = (value) => new TextEncoder().encode(value);
const fixture = JSON.parse(
  await readFile(
    new URL(
      `../../tests/archive/${Object.keys(archive.files)[0]}`,
      import.meta.url,
    ),
  ),
);

test("browser format decrypts published Python compatibility vectors", async () => {
  for (const filename of Object.keys(archive.files).filter(
    (_, index) => index % 100 === 0,
  )) {
    const value = JSON.parse(
      await readFile(
        new URL(`../../tests/archive/${filename}`, import.meta.url),
      ),
    );
    const result = await decryptBytes(
      encode(JSON.stringify(value.envelope)),
      phrase,
    );
    assert.equal(
      Buffer.from(result.bytes).toString("hex"),
      value.plaintext_hex,
    );
    assert.equal(result.filename, value.expected_filename);
  }
});
test("Python CLI implementation decrypts a browser-created Unicode/binary container", async () => {
  const bytes = Uint8Array.from([
    ...encode("Browser interoperability: Ẹ káàárọ̀ 🌍"),
    0,
    255,
    13,
  ]);
  const filename = "Ẹ káàárọ̀-🌍.bin";
  const encrypted = await encryptBytes(bytes, phrase, filename);
  const code =
    "import sys,json;from pathlib import Path;from encryption_workbench import decrypt_bytes;index=json.loads(Path('tests/archive/index.json').read_text());r=decrypt_bytes(sys.stdin.buffer.read(),index['public_regression_passphrase']);print(json.dumps({'hex':r.data.hex(),'filename':r.filename}))";
  const process = spawnSync(
    "uv",
    ["run", "--project", root, "python", "-c", code],
    { input: encrypted, cwd: root, encoding: "utf8" },
  );
  assert.equal(process.status, 0, process.stderr);
  const result = JSON.parse(process.stdout);
  assert.equal(result.hex, Buffer.from(bytes).toString("hex"));
  assert.equal(result.filename, filename);
});
test("empty and binary browser round trips use fresh randomness", async () => {
  for (const bytes of [
    new Uint8Array(),
    Uint8Array.from([0, 1, 127, 128, 255]),
    encode("Ẹ káàárọ̀ 🌍"),
  ]) {
    const first = await encryptBytes(bytes, phrase);
    const second = await encryptBytes(bytes, phrase);
    assert.notDeepEqual(first, second);
    assert.deepEqual((await decryptBytes(first, phrase)).bytes, bytes);
    const a = JSON.parse(new TextDecoder().decode(first)),
      b = JSON.parse(new TextDecoder().decode(second));
    assert.notEqual(a.kdf.salt, b.kdf.salt);
    assert.notEqual(a.cipher.iv, b.cipher.iv);
  }
});
test("wrong passphrase, modified tag, salt and nonce produce the same authentication error", async () => {
  const original = fixture.envelope;
  await assert.rejects(
    decryptBytes(encode(JSON.stringify(original)), "WRONG-PUBLIC-EXAMPLE"),
    (error) =>
      error instanceof AuthenticationError &&
      error.message === AUTHENTICATION_MESSAGE,
  );
  for (const field of ["ciphertext", "salt", "iv"]) {
    const value = structuredClone(original),
      parent =
        field === "salt" ? value.kdf : field === "iv" ? value.cipher : value;
    const bytes = fromBase64(parent[field]);
    bytes[0] ^= 1;
    parent[field] = toBase64(bytes);
    await assert.rejects(
      decryptBytes(encode(JSON.stringify(value)), phrase),
      (error) =>
        error instanceof AuthenticationError &&
        error.message === AUTHENTICATION_MESSAGE,
    );
  }
});
test("inspection reports structure without claiming authentication", () => {
  const result = inspectBytes(encode(JSON.stringify(fixture.envelope)));
  assert.equal(result.authenticated, false);
  assert.equal(result.kdf.iterations, 600000);
  assert.equal(Object.hasOwn(result, "filename"), false);
});
test("strict JSON rejects duplicate and escaped duplicate keys, floats and unsafe integers", () => {
  for (const text of [
    '{"version":1,"version":1}',
    '{"version":1,"\\u0076ersion":1}',
    '{"kdf":{"salt":"a","salt":"b"}}',
    '{"version":1.0}',
    '{"version":1e0}',
    '{"version":9007199254740992}',
    "[]",
    "null trailing",
    '{"x":NaN}',
    '{"x":1,}',
    '{"x":"\\q"}',
  ])
    assert.throws(() => strictJSON(text), FormatError);
  const object = strictJSON('{"__proto__":{"polluted":true}}');
  assert.equal(Object.getPrototypeOf(object), null);
  assert.equal(Object.prototype.polluted, undefined);
});
test("unsupported work factors, algorithms, fields and version types fail closed", async () => {
  for (const change of [
    (value) => (value.kdf.iterations = 1),
    (value) => (value.kdf.iterations = 1e100),
    (value) => (value.cipher.name = "AES-CBC"),
    (value) => (value.cipher.tagLength = 32),
    (value) => (value.version = true),
    (value) => (value.extra = "unknown"),
  ]) {
    const value = structuredClone(fixture.envelope);
    change(value);
    await assert.rejects(
      decryptBytes(encode(JSON.stringify(value)), phrase),
      FormatError,
    );
  }
});
test("base64 stays bounded and handles one-megabyte data without regex recursion", () => {
  const bytes = new Uint8Array(1024 * 1024);
  bytes[123] = 255;
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  for (const value of ["AAAA====", "AA", "A B=", "AB==", "???="])
    assert.throws(() => fromBase64(value), FormatError);
});
test("limits and invalid passphrases are checked before encryption", async () => {
  await assert.rejects(
    encryptBytes(new Uint8Array(MAX_PLAINTEXT + 1), phrase),
    FormatError,
  );
  for (const invalid of ["", "short", "x".repeat(4097), "\ud800".repeat(12)])
    await assert.rejects(encryptBytes(encode("public"), invalid), FormatError);
  await assert.rejects(
    encryptBytes(encode("public"), phrase, "\0"),
    FormatError,
  );
});
test("canonical JSON matches Python ASCII escaping and ordered keys", () => {
  assert.equal(
    canonical({ z: 1, a: "Ẹ 🌍\x7f" }),
    '{"a":"\\u1eb8 \\ud83c\\udf0d\\u007f","z":1}',
  );
});
