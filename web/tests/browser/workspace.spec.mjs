import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile, mkdir } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const index = JSON.parse(
  await readFile(new URL("../../../tests/archive/index.json", import.meta.url)),
);
const publicPhrase = index.public_regression_passphrase;
const fixture = JSON.parse(
  await readFile(
    new URL(
      `../../../tests/archive/${Object.keys(index.files)[0]}`,
      import.meta.url,
    ),
  ),
);

test("text encryption and authenticated decryption stay local and clear completely", async ({
  page,
}, info) => {
  const requests = [],
    errors = [];
  page.on("request", (request) => requests.push(request));
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page
    .getByLabel("Text to encrypt", { exact: true })
    .fill("Public browser test: Ẹ káàárọ̀ 🌍");
  await page.getByLabel("Passphrase", { exact: true }).fill(publicPhrase);
  await page
    .getByLabel("Confirm passphrase", { exact: true })
    .fill(publicPhrase);
  await page
    .getByRole("button", { name: "Encrypt locally", exact: true })
    .click();
  await expect(page.locator("#result-title")).toHaveText("Container created.");
  const encrypted = await page.locator("#output").inputValue();
  expect(JSON.parse(encrypted).kdf.iterations).toBe(600000);
  await page
    .getByRole("button", { name: "Open this container", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Decrypt & authenticate", exact: true })
    .click();
  await expect(page.locator("#result-title")).toHaveText(
    "Contents authenticated.",
  );
  await expect(page.locator("#output")).toHaveValue(
    "Public browser test: Ẹ káàárọ̀ 🌍",
  );
  expect(
    requests.filter((request) => !["GET", "HEAD"].includes(request.method())),
  ).toEqual([]);
  expect(
    requests.filter(
      (request) =>
        /^https?:/.test(request.url()) &&
        new URL(request.url()).origin !== new URL(page.url()).origin,
    ),
  ).toEqual([]);
  expect(errors).toEqual([]);
  await mkdir("../docs/browser", { recursive: true });
  await page.screenshot({
    path: `../docs/browser/workspace-${info.project.name}.png`,
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Clear workspace", exact: true })
    .click();
  await expect(page.locator("#passphrase")).toHaveValue("");
  await expect(page.locator("#content")).toHaveValue("");
  await expect(page.locator("#output")).toBeHidden();
  await expect(page.locator("#download")).toBeHidden();
  const storage = await page.evaluate(() => ({ ...localStorage }));
  expect(JSON.stringify(storage)).not.toContain(publicPhrase);
  expect(JSON.stringify(storage)).not.toContain("Public browser test");
});

test("browser decrypts a Python-created binary file and emits a CLI-compatible encrypted download", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("radio", { name: "Decrypt", exact: true }).check();
  await page.getByRole("radio", { name: "File", exact: true }).check();
  await page
    .getByLabel("Choose a file", { exact: true })
    .setInputFiles({
      name: "public-cli.enc",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify(fixture.envelope)),
    });
  await page.getByLabel("Passphrase", { exact: true }).fill(publicPhrase);
  await page
    .getByRole("button", { name: "Decrypt & authenticate", exact: true })
    .click();
  await expect(page.locator("#authentication")).toHaveText(
    "AUTHENTICATION PASSED",
  );
  const [decrypted] = await Promise.all([
    page.waitForEvent("download"),
    page
      .getByRole("button", { name: "Download recovered file", exact: true })
      .click(),
  ]);
  expect((await readFile(await decrypted.path())).toString("hex")).toBe(
    fixture.plaintext_hex,
  );
  await page.getByRole("radio", { name: "Encrypt", exact: true }).check();
  await page
    .getByLabel("Choose a file", { exact: true })
    .setInputFiles({
      name: "public-🌍.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.from([0, 1, 127, 128, 255]),
    });
  await page
    .getByLabel("Confirm passphrase", { exact: true })
    .fill(publicPhrase);
  await page
    .getByRole("button", { name: "Encrypt locally", exact: true })
    .click();
  await expect(page.locator("#result-title")).toHaveText("Container created.");
  const [encrypted] = await Promise.all([
    page.waitForEvent("download"),
    page
      .getByRole("button", { name: "Download encrypted file", exact: true })
      .click(),
  ]);
  const bytes = await readFile(await encrypted.path());
  const process = spawnSync(
    "uv",
    [
      "run",
      "--project",
      root,
      "python",
      "-c",
      "import sys,json;from pathlib import Path;from encryption_workbench import decrypt_bytes;i=json.loads(Path('tests/archive/index.json').read_text());r=decrypt_bytes(sys.stdin.buffer.read(),i['public_regression_passphrase']);print(json.dumps({'hex':r.data.hex(),'filename':r.filename}))",
    ],
    { input: bytes, encoding: "utf8", cwd: root },
  );
  expect(process.status, process.stderr).toBe(0);
  expect(JSON.parse(process.stdout)).toEqual({
    hex: "00017f80ff",
    filename: "public-🌍.bin",
  });
});

test("wrong passwords and malformed containers release no output; inspection stays unauthenticated", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("radio", { name: "Decrypt", exact: true }).check();
  await page
    .getByLabel("Encrypted container (JSON)", { exact: true })
    .fill(JSON.stringify(fixture.envelope));
  await page
    .getByLabel("Passphrase", { exact: true })
    .fill("WRONG-PUBLIC-EXAMPLE");
  await page
    .getByRole("button", { name: "Decrypt & authenticate", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText(
    "incorrect passphrase or damaged container",
  );
  await expect(page.locator("#output")).toBeHidden();
  await expect(page.locator("#download")).toBeHidden();
  await page
    .getByRole("radio", { name: "Inspect header", exact: true })
    .check();
  await page
    .getByRole("button", { name: "Inspect public header", exact: true })
    .click();
  await expect(page.locator("#authentication")).toContainText(
    "NOT AUTHENTICATED",
  );
  await expect(page.locator("#header-report")).toContainText(
    '"authenticated": false',
  );
  await page
    .getByLabel("Encrypted container (JSON)", { exact: true })
    .fill('{"version":1,"version":1}');
  await page
    .getByRole("button", { name: "Inspect public header", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("Duplicate JSON keys");
  await expect(page.locator("#download")).toBeHidden();
});

test("cancellation, confirmation checks, themes and keyboard access work", async ({
  page,
}) => {
  await page.goto("/");
  await page
    .getByLabel("Text to encrypt", { exact: true })
    .fill("Public cancellation test");
  await page.getByLabel("Passphrase", { exact: true }).fill(publicPhrase);
  await page
    .getByLabel("Confirm passphrase", { exact: true })
    .fill("DIFFERENT-PUBLIC-EXAMPLE");
  await page
    .getByRole("button", { name: "Encrypt locally", exact: true })
    .click();
  await expect(page.getByRole("alert")).toContainText("do not match");
  await page
    .getByLabel("Confirm passphrase", { exact: true })
    .fill(publicPhrase);
  await page
    .getByRole("button", { name: "Encrypt locally", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Clear workspace", exact: true })
    .click();
  await expect(page.locator("#passphrase")).toHaveValue("");
  await expect(page.locator("#download")).toBeHidden();
  await page.getByRole("button", { name: "Switch theme", exact: true }).click();
  const theme = await page.locator("html").getAttribute("data-theme");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to workspace", exact: true }),
  ).toBeFocused();
});

test("both themes, each action and narrow screens pass accessibility checks", async ({
  page,
}) => {
  await page.goto("/");
  for (const theme of [0, 1]) {
    if (theme)
      await page
        .getByRole("button", { name: "Switch theme", exact: true })
        .click();
    for (const name of ["Encrypt", "Decrypt", "Inspect header"]) {
      await page.getByRole("radio", { name, exact: true }).check();
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    }
  }
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
});
