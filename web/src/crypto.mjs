// The same version-one envelope as the Python CLI. Web Crypto provides all
// cryptographic operations; this module only validates and serializes containers.
export const MAX_PLAINTEXT = 16 * 1024 * 1024;
export const MAX_METADATA = 4096;
const MAX_CIPHERTEXT = MAX_PLAINTEXT + MAX_METADATA + 4 + 16;
export const MAX_ENVELOPE = Math.ceil(MAX_CIPHERTEXT / 3) * 4 + 4096;
export const ITERATIONS = 600000;
export const AUTHENTICATION_MESSAGE =
  "Authentication failed: incorrect passphrase or damaged container.";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class FormatError extends Error {}
export class AuthenticationError extends Error {}
export function canonical(value) {
  const ordered = (item) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(
          Object.keys(item)
            .sort()
            .map((key) => [key, ordered(item[key])]),
        )
      : item;
  return JSON.stringify(ordered(value)).replace(
    /[\u007f-\uffff]/g,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}
export function toBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 8192)
    binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
  return btoa(binary);
}
export function fromBase64(value, { exact, maximum = MAX_CIPHERTEXT } = {}) {
  if (
    typeof value !== "string" ||
    value.length > Math.ceil(maximum / 3) * 4 ||
    value.length % 4 !== 0 ||
    /[^A-Za-z0-9+/=]/.test(value)
  )
    throw new FormatError("Invalid or oversized base64 field.");
  let bytes;
  try {
    bytes = Uint8Array.from(atob(value), (character) =>
      character.charCodeAt(0),
    );
  } catch {
    throw new FormatError("Invalid base64 field.");
  }
  if (
    bytes.length > maximum ||
    (exact !== undefined && bytes.length !== exact) ||
    toBase64(bytes) !== value
  )
    throw new FormatError("Noncanonical base64 or incorrect field length.");
  return bytes;
}

// JSON.parse accepts duplicate keys and erases the distinction between 1 and
// 1.0. This bounded reader preserves the CLI's strict integer/key constraints.
export function strictJSON(text) {
  if (typeof text !== "string" || text.length > MAX_ENVELOPE)
    throw new FormatError("Container exceeds the browser limit.");
  let index = 0;
  const whitespace = () => {
    while (/[ \t\r\n]/.test(text[index] || "") && index < text.length)
      index += 1;
  };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      if (text[index] === "\\") {
        index += 2;
        continue;
      }
      if (text[index++] === '"') {
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          break;
        }
      }
    }
    throw new FormatError("Invalid JSON string.");
  };
  const read = (depth) => {
    whitespace();
    if (depth > 8) throw new FormatError("Container nesting is too deep.");
    if (text[index] === '"') return string();
    if (text[index] === "{") {
      index += 1;
      whitespace();
      const value = Object.create(null);
      if (text[index] === "}") {
        index += 1;
        return value;
      }
      for (let count = 0; count < 16; count += 1) {
        whitespace();
        if (text[index] !== '"') throw new FormatError("Invalid JSON object.");
        const key = string();
        if (Object.hasOwn(value, key))
          throw new FormatError("Duplicate JSON keys are not allowed.");
        whitespace();
        if (text[index++] !== ":")
          throw new FormatError("Invalid JSON object.");
        value[key] = read(depth + 1);
        whitespace();
        const separator = text[index++];
        if (separator === "}") return value;
        if (separator !== ",") throw new FormatError("Invalid JSON object.");
      }
      throw new FormatError("Too many container fields.");
    }
    for (const [word, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ]) {
      if (text.startsWith(word, index)) {
        index += word.length;
        return value;
      }
    }
    const number = text
      .slice(index)
      .match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (
      !number ||
      /[.eE]/.test(number[0]) ||
      !Number.isSafeInteger(Number(number[0]))
    )
      throw new FormatError("Container numbers must be safe integers.");
    index += number[0].length;
    return Number(number[0]);
  };
  const value = read(0);
  whitespace();
  if (index !== text.length) throw new FormatError("Trailing JSON content.");
  return value;
}
function fields(value, expected) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== [...expected].sort().join(",")
  )
    throw new FormatError("Unsupported container fields.");
}
export function parseEnvelope(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_ENVELOPE)
    throw new FormatError("Container exceeds the browser limit.");
  let text;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new FormatError("The container must be UTF-8 JSON.");
  }
  const value = strictJSON(text);
  fields(value, ["format", "version", "kdf", "cipher", "ciphertext"]);
  if (value.format !== "encryption-workbench" || value.version !== 1)
    throw new FormatError("Unsupported container format or version.");
  fields(value.kdf, ["name", "hash", "iterations", "salt"]);
  fields(value.cipher, ["name", "bits", "iv", "tagLength"]);
  if (
    value.kdf.name !== "PBKDF2" ||
    value.kdf.hash !== "SHA-256" ||
    value.kdf.iterations !== ITERATIONS ||
    value.cipher.name !== "AES-GCM" ||
    value.cipher.bits !== 256 ||
    value.cipher.tagLength !== 128
  )
    throw new FormatError("Unsupported cryptographic parameters.");
  const salt = fromBase64(value.kdf.salt, { exact: 16, maximum: 16 });
  const nonce = fromBase64(value.cipher.iv, { exact: 12, maximum: 12 });
  const ciphertext = fromBase64(value.ciphertext);
  if (ciphertext.length < 20)
    throw new FormatError("Truncated authenticated payload.");
  const header = {
    format: value.format,
    version: value.version,
    kdf: value.kdf,
    cipher: value.cipher,
  };
  return { header, salt, nonce, ciphertext };
}
function phrase(value, creating) {
  if (
    typeof value !== "string" ||
    (value.isWellFormed && !value.isWellFormed())
  )
    throw new FormatError("Use valid UTF-8 text for the passphrase.");
  const bytes = encoder.encode(value);
  if (
    !bytes.length ||
    bytes.length > 4096 ||
    (creating && Array.from(value).length < 12)
  )
    throw new FormatError(
      "Use at least 12 characters and at most 4096 UTF-8 bytes.",
    );
  return bytes;
}
async function key(passphrase, salt, creating = false) {
  if (!globalThis.crypto?.subtle)
    throw new FormatError(
      "Web Crypto requires HTTPS or localhost in a supported browser.",
    );
  const material = await crypto.subtle.importKey(
    "raw",
    phrase(passphrase, creating),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function encryptBytes(bytes, passphrase, filename = "file") {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_PLAINTEXT)
    throw new FormatError("The browser supports files up to 16 MiB.");
  if (typeof filename !== "string" || filename.includes("\0"))
    throw new FormatError("Invalid filename metadata.");
  const name = filename.replaceAll("\\", "/").split("/").at(-1) || "file";
  const metadata = encoder.encode(canonical({ filename: name }));
  if (metadata.length > MAX_METADATA)
    throw new FormatError("Filename metadata is too long.");
  const salt = crypto.getRandomValues(new Uint8Array(16)),
    nonce = crypto.getRandomValues(new Uint8Array(12));
  const header = {
    format: "encryption-workbench",
    version: 1,
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: ITERATIONS,
      salt: toBase64(salt),
    },
    cipher: { name: "AES-GCM", bits: 256, iv: toBase64(nonce), tagLength: 128 },
  };
  const payload = new Uint8Array(4 + metadata.length + bytes.length);
  new DataView(payload.buffer).setUint32(0, metadata.length);
  payload.set(metadata, 4);
  payload.set(bytes, 4 + metadata.length);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: encoder.encode(canonical(header)),
      tagLength: 128,
    },
    await key(passphrase, salt, true),
    payload,
  );
  return encoder.encode(
    canonical({ ...header, ciphertext: toBase64(new Uint8Array(encrypted)) }) +
      "\n",
  );
}
export async function decryptBytes(bytes, passphrase) {
  const { header, salt, nonce, ciphertext } = parseEnvelope(bytes);
  const derived = await key(passphrase, salt);
  let plaintext;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: encoder.encode(canonical(header)),
          tagLength: 128,
        },
        derived,
        ciphertext,
      ),
    );
  } catch {
    throw new AuthenticationError(AUTHENTICATION_MESSAGE);
  }
  if (plaintext.length < 4)
    throw new FormatError("Invalid authenticated metadata bounds.");
  const length = new DataView(plaintext.buffer).getUint32(0);
  if (
    !length ||
    length > MAX_METADATA ||
    plaintext.length < length + 4 ||
    plaintext.length - length - 4 > MAX_PLAINTEXT
  )
    throw new FormatError("Invalid authenticated metadata bounds.");
  let metadata;
  try {
    metadata = strictJSON(decoder.decode(plaintext.subarray(4, 4 + length)));
  } catch {
    throw new FormatError("Invalid authenticated metadata.");
  }
  fields(metadata, ["filename"]);
  if (typeof metadata.filename !== "string")
    throw new FormatError("Invalid filename metadata.");
  return { bytes: plaintext.slice(4 + length), filename: metadata.filename };
}
export function inspectBytes(bytes) {
  const { header, ciphertext } = parseEnvelope(bytes);
  return {
    ...header,
    ciphertext_bytes: ciphertext.length,
    authenticated: false,
    note: "Structural inspection only. Decrypt to authenticate.",
  };
}
