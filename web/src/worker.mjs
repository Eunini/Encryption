import { encryptBytes, decryptBytes, inspectBytes } from "./crypto.mjs";
self.onmessage = async ({ data }) => {
  const { id, action, bytes, passphrase, filename } = data;
  try {
    if (action === "inspect") {
      self.postMessage({ id, ok: true, report: inspectBytes(bytes) });
      return;
    }
    const result =
      action === "encrypt"
        ? {
            bytes: await encryptBytes(bytes, passphrase, filename),
            filename: "encrypted-file.enc",
          }
        : action === "decrypt"
          ? await decryptBytes(bytes, passphrase)
          : null;
    if (!result) throw new Error("Unsupported operation.");
    self.postMessage({ id, ok: true, ...result }, [result.bytes.buffer]);
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      message:
        error instanceof Error ? error.message : "Operation could not finish.",
    });
  }
};
