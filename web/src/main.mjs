import "@fontsource-variable/manrope";
import "./style.css";
import { MAX_PLAINTEXT, MAX_ENVELOPE } from "./crypto.mjs";

const $ = (selector) => document.querySelector(selector);
const source = "https://github.com/Eunini/Encryption";
let theme = matchMedia("(prefers-color-scheme: dark)").matches
  ? "dark"
  : "light";
try {
  theme = localStorage.getItem("encryption-theme") || theme;
} catch {
  /* Optional preference. */
}
document.documentElement.dataset.theme = theme;
$("#app").innerHTML = `
<a class="skip" href="#workspace">Skip to workspace</a>
<header><a class="brand" href="./"><span class="brand-mark" aria-hidden="true">EW</span><span>Encryption Workbench<small>BY INIOLUWA ATANDA</small></span></a><nav aria-label="Resources"><a href="${source}" target="_blank" rel="noreferrer">Source code</a><a href="${source}#use" target="_blank" rel="noreferrer">Python CLI</a><button id="theme" class="subtle">Switch theme</button></nav></header>
<main><section class="intro"><p class="eyebrow">A LOCAL WORKSPACE FOR YOUR DATA</p><h1>Encrypt here.<br>Keep your data with you.</h1><p>Protect text and files in your browser, or open a container from the Python CLI. Your inputs stay on this device.</p></section>
<div class="facts"><span>AES-256-GCM</span><span>Authenticated containers</span><span>Up to 16 MiB in the browser</span><span>No account or upload</span></div>
<div class="workspace" id="workspace"><section class="panel input-panel"><div class="panel-heading"><h2>Your workspace</h2><button id="clear" type="button" class="subtle">Clear workspace</button></div>
<form id="crypto-form" autocomplete="off"><fieldset id="inputs"><legend class="sr-only">Encryption inputs</legend><fieldset class="segmented"><legend>What would you like to do?</legend><label><input type="radio" name="action" value="encrypt" checked><span>Encrypt</span></label><label><input type="radio" name="action" value="decrypt"><span>Decrypt</span></label><label><input type="radio" name="action" value="inspect"><span>Inspect header</span></label></fieldset>
<fieldset class="mode"><legend>Input type</legend><label><input type="radio" name="mode" value="text" checked> Text</label><label><input type="radio" name="mode" value="file"> File</label></fieldset>
<div id="text-input"><label id="content-label" for="content">Text to encrypt</label><textarea id="content" rows="7" spellcheck="false" autocomplete="off" placeholder="Write or paste your text here"></textarea></div>
<div id="file-input" hidden><label for="file">Choose a file</label><input id="file" type="file"><p id="file-help" class="fine">File contents and the original filename are encrypted. Maximum plaintext size: 16 MiB.</p></div>
<div id="passphrase-fields"><label for="passphrase">Passphrase</label><div class="password-wrap"><input id="passphrase" type="password" autocomplete="off" spellcheck="false" required><button id="reveal" type="button" class="subtle" aria-label="Show passphrase" aria-pressed="false">Show</button></div><p id="phrase-help" class="fine">Use a strong passphrase with at least 12 characters. There is no recovery key.</p><div id="confirmation-field"><label for="confirmation">Confirm passphrase</label><input id="confirmation" type="password" autocomplete="off" spellcheck="false" required></div></div>
</fieldset><div class="actions"><button type="submit" id="run" class="primary">Encrypt locally</button><button type="button" id="cancel" class="subtle" hidden>Cancel</button></div><p id="status" role="status">Ready. Nothing has been sent or saved.</p></form>
</section><section class="panel result-panel" id="result-panel" tabindex="-1" aria-label="Result"><p class="eyebrow">RESULT</p><h2 id="result-title">Your output appears here.</h2><p id="result-description" class="muted">Choose an action, add your input and run it locally. Results remain in this workspace until you download or clear them.</p><p id="authentication" class="auth-status" hidden></p><label id="output-label" for="output" hidden>Output</label><textarea id="output" readonly spellcheck="false" rows="10" hidden></textarea><pre id="header-report" hidden></pre><div class="result-actions"><button class="primary" id="download" hidden>Download result</button><button class="secondary" id="copy" hidden>Copy container</button><button class="subtle" id="use-result" hidden>Open this container</button></div><p id="output-note" class="fine"></p><div class="result-placeholder" id="placeholder" aria-hidden="true"><span>01</span><div></div><span>LOCAL INPUT → AUTHENTICATED CONTAINER</span></div></section></div>
<section class="details-grid"><article><h2>One format. Two interfaces.</h2><p>The browser and CLI use the same version-one container. Encrypt here and decrypt in Python, or bring a CLI file into this workspace.</p><a href="${source}/blob/main/docs/format.md" target="_blank" rel="noreferrer">Read the container format →</a></article><article><h2>Clear about the boundaries.</h2><p>The browser uses Web Crypto in a worker and does not upload your data. Use Clear workspace to stop a running operation and release the page’s references to your inputs.</p><p class="fine">Browser memory cannot be guaranteed to be erased. This project has not received an independent security audit. The CLI supports files up to 64 MiB.</p><a href="${source}/blob/main/docs/security.md" target="_blank" rel="noreferrer">Read the security notes →</a></article></section>
</main><footer><span>Encryption Workbench · Inioluwa Atanda</span><span>Version-one containers / MIT licensed</span></footer>`;

let worker;
let requestId = 0;
let result;
let busy = false;
const action = () => $('input[name="action"]:checked').value;
const mode = () => $('input[name="mode"]:checked').value;
const encode = (value) => new TextEncoder().encode(value);
const safeFilename = (value) => {
  const name = String(value)
    .replace(/[\\/\x00-\x1f\x7f]/g, "_")
    .slice(0, 200)
    .trim();
  return name && ![".", ".."].includes(name) ? name : "recovered-file.bin";
};
function status(message, error = false) {
  $("#status").textContent = message;
  $("#status").dataset.error = String(error);
  $("#status").setAttribute("role", error ? "alert" : "status");
}
function stop() {
  requestId += 1;
  worker?.terminate();
  worker = undefined;
  busy = false;
  $("#inputs").disabled = false;
  $("#run").disabled = false;
  $("#cancel").hidden = true;
}
function clearResult() {
  result = undefined;
  $("#result-title").textContent = "Your output appears here.";
  $("#result-description").textContent =
    "Your output remains in this workspace until you download or clear it.";
  for (const selector of [
    "#output",
    "#output-label",
    "#header-report",
    "#authentication",
    "#download",
    "#copy",
    "#use-result",
  ])
    $(selector).hidden = true;
  $("#output").value = "";
  $("#header-report").textContent = "";
  $("#output-note").textContent = "";
  $("#placeholder").hidden = false;
}
function configure() {
  stop();
  clearResult();
  const current = action();
  $("#text-input").hidden = mode() !== "text";
  $("#file-input").hidden = mode() !== "file";
  $("#passphrase-fields").hidden = current === "inspect";
  $("#confirmation-field").hidden = current !== "encrypt";
  $("#passphrase").required = current !== "inspect";
  $("#confirmation").required = current === "encrypt";
  $("#passphrase").minLength = current === "encrypt" ? 12 : 1;
  $("#passphrase").type = "password";
  $("#reveal").textContent = "Show";
  $("#reveal").setAttribute("aria-pressed", "false");
  $("#reveal").setAttribute("aria-label", "Show passphrase");
  $("#content-label").textContent =
    current === "encrypt" ? "Text to encrypt" : "Encrypted container (JSON)";
  $("#content").placeholder =
    current === "encrypt"
      ? "Write or paste your text here"
      : "Paste a version-one encrypted container";
  $("#content").maxLength =
    current === "encrypt" ? MAX_PLAINTEXT : MAX_ENVELOPE;
  $("#phrase-help").textContent =
    current === "encrypt"
      ? "Use a strong passphrase with at least 12 characters. There is no recovery key."
      : "Enter the exact passphrase used when the container was created.";
  $("#file-help").textContent =
    current === "encrypt"
      ? "File contents and the original filename are encrypted. Maximum plaintext size: 16 MiB."
      : "Choose a version-one .enc or JSON container. CLI files must contain no more than 16 MiB of plaintext for this browser workspace.";
  $("#file").accept =
    current === "encrypt" ? "" : ".enc,.json,application/json";
  $("#run").textContent = {
    encrypt: "Encrypt locally",
    decrypt: "Decrypt & authenticate",
    inspect: "Inspect public header",
  }[current];
  status(
    current === "inspect"
      ? "Inspection reads public structure. It does not authenticate the contents."
      : "Ready. All processing happens in your browser.",
  );
}
document
  .querySelectorAll('input[name="action"], input[name="mode"]')
  .forEach((input) => input.addEventListener("change", configure));
$("#theme").addEventListener("click", () => {
  theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem("encryption-theme", theme);
  } catch {
    /* Optional preference. */
  }
});
$("#reveal").addEventListener("click", () => {
  const reveal = $("#passphrase").type === "password";
  $("#passphrase").type = reveal ? "text" : "password";
  $("#reveal").textContent = reveal ? "Hide" : "Show";
  $("#reveal").setAttribute(
    "aria-label",
    reveal ? "Hide passphrase" : "Show passphrase",
  );
  $("#reveal").setAttribute("aria-pressed", String(reveal));
});
$("#clear").addEventListener("click", () => {
  stop();
  $("#content").value = "";
  $("#passphrase").value = "";
  $("#confirmation").value = "";
  $("#file").value = "";
  configure();
  status("Workspace cleared. No input or output is saved by this app.");
});
$("#cancel").addEventListener("click", () => {
  stop();
  clearResult();
  status("Operation cancelled. You can retry or clear the workspace.");
});
function complete(data, selectedAction, selectedMode) {
  busy = false;
  $("#inputs").disabled = false;
  $("#run").disabled = false;
  $("#cancel").hidden = true;
  if (!data.ok) {
    clearResult();
    status(data.message, true);
    return;
  }
  result = { ...data, action: selectedAction };
  $("#placeholder").hidden = true;
  $("#result-title").textContent = {
    encrypt: "Container created.",
    decrypt: "Contents authenticated.",
    inspect: "Public header read.",
  }[selectedAction];
  $("#result-description").textContent =
    selectedAction === "encrypt"
      ? "Your text or file is now in an authenticated container. Keep the passphrase separately."
      : selectedAction === "decrypt"
        ? `${data.bytes.length.toLocaleString()} bytes recovered. The authentication check passed.`
        : "These fields describe the container. They have not been authenticated.";
  $("#authentication").hidden = selectedAction === "encrypt";
  $("#authentication").textContent =
    selectedAction === "decrypt"
      ? "AUTHENTICATION PASSED"
      : "STRUCTURE ONLY / NOT AUTHENTICATED";
  $("#download").hidden = false;
  $("#download").textContent =
    selectedAction === "inspect"
      ? "Download header report"
      : selectedAction === "encrypt"
        ? "Download encrypted file"
        : "Download recovered file";
  if (selectedAction === "inspect") {
    $("#header-report").hidden = false;
    $("#header-report").textContent = JSON.stringify(data.report, null, 2);
  } else {
    $("#output-note").textContent =
      selectedAction === "encrypt"
        ? `${data.bytes.length.toLocaleString()} container bytes. Original filename metadata is encrypted.`
        : `Recovered filename: ${safeFilename(data.filename)}. Download to save the full file.`;
    if (selectedAction === "encrypt") {
      $("#copy").hidden = false;
      $("#use-result").hidden = false;
    }
    if (selectedAction === "encrypt" || selectedMode === "text") {
      let text;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(data.bytes);
        if (selectedAction === "decrypt" && text.includes("\0"))
          text = undefined;
      } catch {
        /* Binary data is download-only. */
      }
      if (text !== undefined) {
        $("#output-label").hidden = false;
        $("#output").hidden = false;
        $("#output").value = text.slice(0, 65536);
        if (text.length > 65536)
          $("#output-note").textContent +=
            " Preview limited to 65,536 characters; download contains the full result.";
      }
    }
  }
  status("Operation completed locally.");
  $("#result-panel").focus();
}
$("#crypto-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy || !event.target.reportValidity()) return;
  const selectedAction = action(),
    selectedMode = mode();
  if (
    selectedAction === "encrypt" &&
    $("#passphrase").value !== $("#confirmation").value
  ) {
    status("The two passphrases do not match.", true);
    return;
  }
  clearResult();
  const id = ++requestId;
  busy = true;
  $("#inputs").disabled = true;
  $("#run").disabled = true;
  $("#cancel").hidden = false;
  status("Working locally…");
  try {
    let bytes, filename;
    if (selectedMode === "file") {
      const file = $("#file").files[0];
      if (!file) throw new Error("Choose a file first.");
      if (
        file.size >
        (selectedAction === "encrypt" ? MAX_PLAINTEXT : MAX_ENVELOPE)
      )
        throw new Error(
          "This file exceeds the browser size limit. Use the Python CLI for larger files.",
        );
      filename = file.name;
      bytes = new Uint8Array(await file.arrayBuffer());
    } else {
      bytes = encode($("#content").value);
      filename = "text.txt";
    }
    if (id !== requestId) return;
    worker ||= new Worker(new URL("./worker.mjs", import.meta.url), {
      type: "module",
    });
    worker.onmessage = ({ data }) => {
      if (data.id === requestId) complete(data, selectedAction, selectedMode);
    };
    worker.onerror = () => {
      if (id === requestId) {
        stop();
        clearResult();
        status("The local worker could not finish. You can retry.", true);
      }
    };
    worker.postMessage(
      {
        id,
        action: selectedAction,
        bytes,
        filename,
        passphrase: $("#passphrase").value,
      },
      [bytes.buffer],
    );
  } catch (error) {
    if (id === requestId)
      complete(
        {
          ok: false,
          message:
            error instanceof Error
              ? error.message
              : "Operation could not finish.",
        },
        selectedAction,
        selectedMode,
      );
  }
});
$("#download").addEventListener("click", () => {
  if (!result) return;
  const bytes =
    result.action === "inspect"
      ? JSON.stringify(result.report, null, 2)
      : result.bytes;
  const url = URL.createObjectURL(
    new Blob([bytes], {
      type:
        result.action === "decrypt"
          ? "application/octet-stream"
          : "application/json",
    }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download =
    result.action === "inspect"
      ? "container-header.json"
      : result.action === "encrypt"
        ? "encrypted-file.enc"
        : safeFilename(result.filename);
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$("#copy").addEventListener("click", async () => {
  if (result?.action !== "encrypt") return;
  try {
    await navigator.clipboard.writeText(new TextDecoder().decode(result.bytes));
    status("Encrypted container copied.");
  } catch {
    status(
      "Clipboard access is unavailable. Download the container instead.",
      true,
    );
  }
});
$("#use-result").addEventListener("click", () => {
  if (result?.action !== "encrypt") return;
  const text = new TextDecoder().decode(result.bytes);
  $('input[name="action"][value="decrypt"]').checked = true;
  $('input[name="mode"][value="text"]').checked = true;
  configure();
  $("#content").value = text;
  $("#confirmation").value = "";
  $("#content").focus();
});
addEventListener("pagehide", stop);
configure();
if (!crypto?.subtle || !window.Worker) {
  $("#run").disabled = true;
  status(
    "This workspace needs a browser with Web Crypto and workers, served over HTTPS or localhost.",
    true,
  );
}
