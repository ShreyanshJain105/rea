import { randomBytes } from "node:crypto";
import { lstat, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Source-owned static fixtures: no compiler, target loading or execution.

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixturesDir = resolve(root, "build", "fixtures");

const HEX_PATTERN = /^(?:[0-9a-f]{2})+$/;

/** Bounds-checked replacement for Buffer#set (which can throw late or be misused). */
function setBytes(buffer, data, offset) {
  if (!Number.isInteger(offset) || offset < 0) {
    throw new RangeError(`Invalid offset: ${offset}`);
  }
  if (offset + data.length > buffer.length) {
    throw new RangeError(`Write of ${data.length} bytes at ${offset} exceeds buffer`);
  }
  buffer.set(data, offset);
}

/** Bounds-checked replacement for Buffer#write (which silently truncates). */
function writeString(buffer, text, offset, encoding) {
  const length = Buffer.byteLength(text, encoding);
  if (!Number.isInteger(offset) || offset < 0 || offset + length > buffer.length) {
    throw new RangeError(`String of ${length} bytes at ${offset} exceeds buffer`);
  }
  buffer.write(text, offset, length, encoding);
}

/** Strict hex decoding (Buffer.from(..., "hex") silently drops invalid input). */
function hexToBuffer(hex) {
  if (!HEX_PATTERN.test(hex)) throw new TypeError("Invalid hex string");
  return Buffer.from(hex, "hex");
}

/** Resolve a fixed file name and prove it stays inside the fixtures directory. */
function safeOutputPath(name) {
  if (!/^rea-ghidra-windows(?:-x86)?\.(?:exe|dll)$/.test(name)) {
    throw new Error(`Unexpected fixture name: ${name}`);
  }
  const target = resolve(fixturesDir, name);
  const rel = relative(fixturesDir, target);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path escapes fixtures directory: ${name}`);
  }
  return target;
}

/** Create the output directory and refuse to write through a symlink. */
async function prepareOutputDir() {
  await mkdir(fixturesDir, { recursive: true, mode: 0o755 });
  const info = await lstat(fixturesDir);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error("Fixtures directory must be a real directory");
  }
}

/** Write to an exclusive temp file, then atomically rename into place. */
async function writeFileAtomic(target, data) {
  const temp = `${target}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    await writeFile(temp, data, { flag: "wx", mode: 0o644 });
    await rename(temp, target);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

function buildFixture(architecture, dll) {
  const x86 = architecture === "x86";
  const bytes = Buffer.alloc(dll ? 1024 : 1536);
  const peOffset = 0x80;
  const optionalHeader = peOffset + 24;
  const optionalHeaderSize = x86 ? 0xe0 : 0xf0;
  const sectionTable = optionalHeader + optionalHeaderSize;
  const directories = optionalHeader + (x86 ? 96 : 112);

  writeString(bytes, "MZ", 0, "ascii");
  bytes.writeUInt32LE(peOffset, 0x3c);
  writeString(bytes, "PE\0\0", peOffset, "binary");
  bytes.writeUInt16LE(x86 ? 0x14c : 0x8664, peOffset + 4);
  bytes.writeUInt16LE(dll ? 1 : 2, peOffset + 6);
  bytes.writeUInt16LE(optionalHeaderSize, peOffset + 20);
  bytes.writeUInt16LE(
    (x86 ? 0x102 : 0x22) | (dll ? 0x2000 : 0),
    peOffset + 22,
  );

  bytes.writeUInt16LE(x86 ? 0x10b : 0x20b, optionalHeader);
  bytes.writeUInt32LE(0x200, optionalHeader + 4);
  if (!dll) bytes.writeUInt32LE(0x200, optionalHeader + 8);
  bytes.writeUInt32LE(dll ? 0 : 0x1000, optionalHeader + 16);
  bytes.writeUInt32LE(0x1000, optionalHeader + 20);
  if (x86) bytes.writeUInt32LE(0x400000, optionalHeader + 28);
  else bytes.writeBigUInt64LE(0x1_4000_0000n, optionalHeader + 24);
  bytes.writeUInt32LE(0x1000, optionalHeader + 32);
  bytes.writeUInt32LE(0x200, optionalHeader + 36);
  bytes.writeUInt16LE(6, optionalHeader + 40);
  bytes.writeUInt16LE(6, optionalHeader + 48);
  bytes.writeUInt32LE(dll ? 0x2000 : 0x3000, optionalHeader + 56);
  bytes.writeUInt32LE(0x200, optionalHeader + 60);
  bytes.writeUInt16LE(3, optionalHeader + 68);
  bytes.writeUInt16LE(x86 ? 0x8140 : 0x8160, optionalHeader + 70);
  if (x86) {
    bytes.writeUInt32LE(0x10_0000, optionalHeader + 72);
    bytes.writeUInt32LE(0x1000, optionalHeader + 76);
    bytes.writeUInt32LE(0x10_0000, optionalHeader + 80);
    bytes.writeUInt32LE(0x1000, optionalHeader + 84);
    bytes.writeUInt32LE(16, optionalHeader + 92);
  } else {
    bytes.writeBigUInt64LE(0x10_0000n, optionalHeader + 72);
    bytes.writeBigUInt64LE(0x1000n, optionalHeader + 80);
    bytes.writeBigUInt64LE(0x10_0000n, optionalHeader + 88);
    bytes.writeBigUInt64LE(0x1000n, optionalHeader + 96);
    bytes.writeUInt32LE(16, optionalHeader + 108);
  }

  writeString(bytes, ".text", sectionTable, "ascii");
  bytes.writeUInt32LE(dll ? 0x180 : 0x50, sectionTable + 8);
  bytes.writeUInt32LE(0x1000, sectionTable + 12);
  bytes.writeUInt32LE(0x200, sectionTable + 16);
  bytes.writeUInt32LE(0x200, sectionTable + 20);
  bytes.writeUInt32LE(0x6000_0020, sectionTable + 36);

  // EXE entry returns zero. DLL caller adds one to the callee's 42.
  setBytes(
    bytes,
    Buffer.from(
      dll
        ? [0xe8, 0x0b, 0, 0, 0, 0x83, 0xc0, 1, 0xc3]
        : [0xe8, 0x0b, 0, 0, 0, 0xe8, 0x16, 0, 0, 0, 0x31, 0xc0, 0xc3],
    ),
    0x200,
  );
  setBytes(bytes, Buffer.from([0xb8, 0x2a, 0, 0, 0, 0xc3]), 0x210);

  if (!dll) {
    const dataSection = sectionTable + 40;
    writeString(bytes, ".data", dataSection, "ascii");
    bytes.writeUInt32LE(0x20, dataSection + 8);
    bytes.writeUInt32LE(0x2000, dataSection + 12);
    bytes.writeUInt32LE(0x200, dataSection + 16);
    bytes.writeUInt32LE(0x400, dataSection + 20);
    bytes.writeUInt32LE(0xc000_0040, dataSection + 36);
    bytes.writeUInt32LE(0x1122_3344, 0x400);
    const referenceInstructions = x86
      ? [
          "ba00204000", // MOV EDX, address: DATA only.
          "a100204000", // MOV EAX, [address]: READ.
          "a304204000", // MOV [address], EAX: WRITE.
          "ba10204000", // Indexed base, unknown ECX.
          "85db", // TEST EBX, EBX: two candidate bases.
          "7405", // JZ over the alternate base.
          "ba18204000", // MOV EDX, alternate base.
          "c6040a01", // MOV byte [EDX + ECX], 1.
          "ffd7", // CALL EDI: unknown target.
          "c3",
        ]
      : [
          "488d15d90f0000", // LEA RDX, [RIP + displacement]: DATA.
          "8b05d30f0000", // MOV EAX, [RIP + displacement]: READ.
          "8905d10f0000", // MOV [RIP + displacement], EAX: WRITE.
          "488d15d60f0000", // Indexed base, unknown RCX.
          "85db", // TEST EBX, EBX: two candidate bases.
          "7407", // JZ over the alternate base.
          "488d15d30f0000", // LEA RDX, alternate base.
          "c6040a01", // MOV byte [RDX + RCX], 1.
          "41ffd0", // CALL R8: unknown target.
          "c3",
        ];
    setBytes(bytes, hexToBuffer(referenceInstructions.join("")), 0x220);
  }

  if (dll) {
    // Export both functions; an entry-point-free library is discovered by exports.
    bytes.writeUInt32LE(0x1040, directories);
    bytes.writeUInt32LE(0x130, directories + 4);
    const exports = 0x240;
    bytes.writeUInt32LE(0x1100, exports + 12);
    bytes.writeUInt32LE(1, exports + 16);
    bytes.writeUInt32LE(2, exports + 20);
    bytes.writeUInt32LE(2, exports + 24);
    bytes.writeUInt32LE(0x1080, exports + 28);
    bytes.writeUInt32LE(0x1088, exports + 32);
    bytes.writeUInt32LE(0x1090, exports + 36);
    bytes.writeUInt32LE(0x1000, 0x280);
    bytes.writeUInt32LE(0x1010, 0x284);
    bytes.writeUInt32LE(0x1120, 0x288);
    bytes.writeUInt32LE(0x1140, 0x28c);
    bytes.writeUInt16LE(0, 0x290);
    bytes.writeUInt16LE(1, 0x292);
    writeString(bytes, "rea-fixture.dll\0", 0x300, "binary");
    writeString(bytes, "fixture_caller\0", 0x320, "binary");
    writeString(bytes, "fixture_return42\0", 0x340, "binary");
  }

  return bytes;
}

await prepareOutputDir();

for (const architecture of ["x86_64", "x86"]) {
  for (const dll of [false, true]) {
    const x86 = architecture === "x86";
    const output = safeOutputPath(
      `rea-ghidra-windows${x86 ? "-x86" : ""}.${dll ? "dll" : "exe"}`,
    );
    await writeFileAtomic(output, buildFixture(architecture, dll));
    if (!x86 && !dll) process.stdout.write(`${output}\n`);
  }
}
