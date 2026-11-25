#!/usr/bin/env node
/**
 * sealed -- the ecosystem's container files, and the first file-extension convention.
 *
 * WHAT THIS ESTABLISHES
 * ---------------------
 * A file ending in `.sealed` is an AES-256-GCM envelope whose key is protected with DPAPI for this
 * machine. It is readable and writable by this ecosystem's own tooling and by nothing else: a text
 * reader, a grep, an editor, or an agent that opens files by extension gets ciphertext. That is the
 * whole point of giving it its own extension rather than leaving a secret in a `.txt` beside the thing
 * it protects -- which is exactly the state this tool was written to fix (a code-signing pfx and its
 * password, in the same directory, in the same format, under the same ACL).
 *
 * The container bytes are volcano-separator's, deliberately rather than by imitation: MAGIC `VSEP1`,
 * a version byte, a 12-byte nonce, the plaintext length as a signed 64-bit little-endian value, the
 * ciphertext and the 16-byte GCM tag. A `.sealed` file therefore opens with that project's own
 * `unseal` as well, and a future reader has one format to learn instead of two.
 *
 *   seal <file> [out]     encrypt; default output is <file>.sealed
 *   open <file> [out]     decrypt; without an output it writes to stdout
 *   info <file>           what the container says about itself, without the key
 *
 * WHAT IT DOES NOT DO, stated plainly because a sealed file invites assumptions:
 *   - it does not protect against code running as this account, or as SYSTEM. The key blob is bound to
 *     the machine and its ACL is what narrows it to this account; DPAPI scope here is LocalMachine, the
 *     same choice the existing tooling makes, so any account that can read the blob can unseal.
 *   - it does not make the file tamper-proof. GCM refuses a modified ciphertext, which is integrity
 *     against accident and casual editing, not against an attacker who can replace the key blob too.
 *   - it does not shred. The plaintext you seal is still on the disk until you delete it, and possibly
 *     in whatever wrote it.
 *
 * A sealed file is verified by round-trip BEFORE it is written: the bytes are decrypted again in
 * memory and compared. Writing a container that cannot be opened is worse than writing nothing, and
 * the cost of proving it is one comparison.
 */
import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const MAGIC = "VSEP1";
const VERSION = 1;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = MAGIC.length + 1 + NONCE_LEN + 8;
const KEY_LEN = 32;

const here = dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const KEY_FILE = join(here, "sealed.key");
const KEYPROTECT = "E:\\volcano-separator\\bin\\keyprotect.ps1";

const b64 = (buf) => Buffer.from(buf).toString("base64");

function ps(args) {
  const r = spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", KEYPROTECT, ...args],
    { encoding: "utf8", timeout: 60000 });
  let parsed = null;
  try { parsed = JSON.parse(String(r.stdout ?? "").trim()); } catch { /* left null */ }
  return parsed ?? { ok: false, detail: String(r.stderr ?? r.stdout ?? "no output from keyprotect").trim() };
}

/** The key, created on first use. Never written in the clear: DPAPI protects it before it touches disk. */
function getOrCreateKey() {
  const tmp = mkdtempSync(join(tmpdir(), "sealed-"));
  try {
    if (existsSync(KEY_FILE)) {
      const inFile = join(tmp, "blob.txt");
      const outFile = join(tmp, "raw.txt");
      writeFileSync(inFile, readFileSync(KEY_FILE, "utf8").trim(), "ascii");
      const r = ps(["-Action", "unprotect", "-In", inFile, "-Out", outFile]);
      if (!r.ok) throw new Error(`could not unprotect the key: ${r.detail}`);
      const raw = Buffer.from(readFileSync(outFile, "utf8").trim(), "base64");
      if (raw.length !== KEY_LEN) throw new Error(`the key is ${raw.length} bytes, not ${KEY_LEN}`);
      return { key: raw, created: false };
    }
    const raw = randomBytes(KEY_LEN);
    const inFile = join(tmp, "raw.txt");
    const outFile = join(tmp, "blob.txt");
    writeFileSync(inFile, b64(raw), "ascii");
    const r = ps(["-Action", "protect", "-In", inFile, "-Out", outFile]);
    // Refuse to go on: a container whose key was never written is a file that is gone.
    if (!r.ok) throw new Error(`could not protect the key, so nothing will be sealed: ${r.detail}`);
    writeFileSync(KEY_FILE, readFileSync(outFile, "utf8").trim(), "ascii");
    return { key: raw, created: true };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function seal(key, plain) {
  const nonce = randomBytes(NONCE_LEN);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  const size = Buffer.alloc(8);
  size.writeBigInt64LE(BigInt(plain.length));
  return Buffer.concat([Buffer.from(MAGIC, "ascii"), Buffer.from([VERSION]), nonce, size, ct, c.getAuthTag()]);
}

function unseal(key, blob) {
  if (blob.length < HEADER_LEN + TAG_LEN) throw new Error("too short to be one of ours");
  if (blob.subarray(0, MAGIC.length).toString("ascii") !== MAGIC) throw new Error("not a " + MAGIC + " container");
  if (blob[MAGIC.length] !== VERSION) throw new Error(`container version ${blob[MAGIC.length]}, not ${VERSION}`);
  let o = MAGIC.length + 1;
  const nonce = blob.subarray(o, o + NONCE_LEN); o += NONCE_LEN;
  const size = Number(blob.readBigInt64LE(o)); o += 8;
  const ct = blob.subarray(o, blob.length - TAG_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  if (ct.length !== size) throw new Error(`the container says ${size} bytes but carries ${ct.length}`);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

const isContainer = (blob) => blob.length >= MAGIC.length + 1 && blob.subarray(0, MAGIC.length).toString("ascii") === MAGIC;

function main(argv) {
  const [cmd, ...rest] = argv;
  // A bare "-" is the standard-input sentinel and must survive the flag filter, or it is eaten and
// the output path silently becomes the input path.
  const positional = rest.filter((a) => a === "-" || !a.startsWith("-"));

  if (cmd === "info") {
    const p = resolve(positional[0] ?? "");
    if (!existsSync(p)) { console.error(`no such file: ${p}`); return 1; }
    const blob = readFileSync(p);
    if (!isContainer(blob)) { console.log(`${p}\n  not a ${MAGIC} container`); return 1; }
    const size = Number(blob.readBigInt64LE(MAGIC.length + 1 + NONCE_LEN));
    console.log(`${p}`);
    console.log(`  container   ${MAGIC} version ${blob[MAGIC.length]}`);
    console.log(`  plaintext   ${size} bytes`);
    console.log(`  on disk     ${blob.length} bytes`);
    console.log(`  key file    ${KEY_FILE}${existsSync(KEY_FILE) ? "" : "  (missing)"}`);
    return 0;
  }

  if (cmd === "seal") {
    if (!positional[0]) { console.error("usage: seal <file|-> [out]"); return 2; }
    // `-` reads the plaintext from standard input, so a generated secret can be sealed WITHOUT ever
    // existing in the clear -- not even for the moment a temp file would live. The caller pipes it in.
    const fromStdin = positional[0] === "-";
    const src = fromStdin ? null : resolve(positional[0]);
    if (fromStdin && !positional[1]) { console.error("sealing from stdin needs an explicit output path"); return 2; }
    // THE EXTENSION IS REPLACED, NOT APPENDED. `.sealed` is the file's TYPE, so `pfx-password.txt`
    // becomes `pfx-password.sealed` and not `pfx-password.txt.sealed` -- a suffix stacked on the old
    // extension describes the file it used to be, and what a reader needs to know is what it is now.
    const stem = fromStdin ? null : src.replace(/\.[^.\\/]+$/, "");
    const dst = resolve(positional[1] ?? `${stem}.sealed`);
    if (!fromStdin && !existsSync(src)) { console.error(`no such file: ${src}`); return 1; }
    if (existsSync(dst)) { console.error(`refusing to overwrite ${dst}`); return 1; }
    const plain = fromStdin ? readFileSync(0) : readFileSync(src);
    if (isContainer(plain)) { console.error(`${src} is already a container`); return 1; }
    const { key, created } = getOrCreateKey();
    const blob = seal(key, plain);
    // Prove it opens before writing it. A container nobody can open is worse than no container.
    const back = unseal(key, blob);
    if (back.length !== plain.length || !timingSafeEqual(back, plain)) {
      console.error("round-trip check FAILED; nothing was written");
      return 1;
    }
    writeFileSync(dst, blob);
    console.log(`sealed ${fromStdin ? "(standard input)" : src}`);
    console.log(`  -> ${dst}  (${blob.length} bytes from ${plain.length})${created ? "  [key created: " + KEY_FILE + "]" : ""}`);
    console.log("  round-trip verified before writing." + (fromStdin
      ? " Nothing plaintext was written anywhere."
      : " The plaintext file is still there: delete it when you are ready,"));
    if (!fromStdin) console.log("  and remember the seal does not shred.");
    return 0;
  }

  if (cmd === "open") {
    if (!positional[0]) { console.error("usage: open <file> [out]"); return 2; }
    const src = resolve(positional[0]);
    if (!existsSync(src)) { console.error(`no such file: ${src}`); return 1; }
    const blob = readFileSync(src);
    const { key } = getOrCreateKey();
    let plain;
    try { plain = unseal(key, blob); }
    catch (e) { console.error(`cannot open ${src}: ${e.message}`); return 1; }
    if (positional[1]) {
      const dst = resolve(positional[1]);
      if (existsSync(dst)) { console.error(`refusing to overwrite ${dst}`); return 1; }
      writeFileSync(dst, plain);
      console.log(`opened ${src} -> ${dst} (${plain.length} bytes)`);
    } else {
      process.stdout.write(plain);
    }
    return 0;
  }

  console.error("usage: seal.mjs <seal|open|info> ...");
  return 2;
}

process.exit(main(process.argv.slice(2)));
