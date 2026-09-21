/*
 * Parser for Mach-O "fat" (universal) binaries -- the container Apple uses
 * to ship one file containing native code for several CPU architectures
 * (e.g. x86_64 + arm64 in the same .dylib, or a Universal 2 app binary).
 *
 * Format background:
 *
 *   A fat binary starts with a fat_header, ALWAYS BIG-ENDIAN regardless of
 *   which architectures it contains (this predates Mach-O's own per-slice
 *   byte order and has never changed):
 *
 *     struct fat_header {
 *       uint32_t magic;      // FAT_MAGIC 0xcafebabe (32-bit offsets/sizes)
 *                             // or FAT_MAGIC_64 0xcafebabf (64-bit offsets,
 *                             // used by Xcode 15+ for arm64e-heavy builds)
 *       uint32_t nfat_arch;  // number of fat_arch entries that follow
 *     }
 *
 *   followed by nfat_arch fixed-size records, each describing one thin
 *   (single-architecture) Mach-O slice living elsewhere in the same file:
 *
 *     struct fat_arch {       // FAT_MAGIC (32-bit)
 *       cpu_type_t    cputype;
 *       cpu_subtype_t cpusubtype;
 *       uint32_t      offset;   // file offset of this slice
 *       uint32_t      size;     // length of this slice, in bytes
 *       uint32_t      align;    // slice's required alignment, as log2
 *     }
 *
 *     struct fat_arch_64 {     // FAT_MAGIC_64
 *       cpu_type_t    cputype;
 *       cpu_subtype_t cpusubtype;
 *       uint64_t      offset;
 *       uint64_t      size;
 *       uint32_t      align;
 *       uint32_t      reserved;
 *     }
 *
 *   Extracting one architecture is then just a byte-range copy of
 *   [offset, offset+size) -- confirmed against `llvm-lipo -thin` while
 *   building this tool's ground-truth fixtures: the extracted bytes are
 *   byte-for-byte identical to what lipo itself produces. There is no
 *   compression, encryption, or any other transformation involved.
 *
 *   Each slice is itself an ordinary thin Mach-O file, starting with its
 *   own mach_header (32-bit, magic 0xfeedface) or mach_header_64 (64-bit,
 *   magic 0xfeedfacf) -- both little-endian on every architecture Apple
 *   ships today (x86, x86_64, arm, arm64). This tool peeks at that thin
 *   header too, purely as a cross-check that it's internally consistent
 *   with what the fat_arch entry claims (a mismatch would mean a
 *   corrupted or hand-edited fat binary).
 *
 *   A single-architecture Mach-O file (not fat at all) starts directly
 *   with one of those same thin magics instead of the fat magic -- this
 *   tool recognizes that case explicitly rather than just failing, since
 *   "is my binary actually universal?" is exactly the question people
 *   bring to a tool like this.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.MachOFatSplitter = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class MachOParseError extends Error {}

  const FAT_MAGIC = 0xcafebabe;
  const FAT_MAGIC_64 = 0xcafebabf;
  // The byte-swapped forms would appear if a fat header were ever written
  // in little-endian order. In practice this has never shipped, but we
  // recognize it so we can give a precise error instead of a generic one.
  const FAT_CIGAM = 0xbebafeca;
  const FAT_CIGAM_64 = 0xbebafecf;

  const MH_MAGIC = 0xfeedface; // 32-bit thin Mach-O, native (little) endian
  const MH_MAGIC_64 = 0xfeedfacf; // 64-bit thin Mach-O, native (little) endian
  const MH_CIGAM = 0xcefaedfe; // 32-bit thin Mach-O, byte-swapped
  const MH_CIGAM_64 = 0xcffaedfe; // 64-bit thin Mach-O, byte-swapped

  // ---------------------------------------------------------------------
  // CPU type / subtype tables (mach/machine.h). Not exhaustive -- unknown
  // values fall back to a hex display rather than a guess.
  // ---------------------------------------------------------------------

  const CPU_ARCH_ABI64 = 0x01000000;
  const CPU_ARCH_ABI64_32 = 0x02000000;

  const CPU_TYPE_NAMES = {
    1: 'vax',
    6: 'mc680x0',
    7: 'i386',
    [0x01000007]: 'x86_64',
    8: 'mips',
    10: 'mc98000',
    11: 'hppa',
    12: 'arm',
    [0x0100000c]: 'arm64',
    [0x0200000c]: 'arm64_32',
    13: 'mc88000',
    14: 'sparc',
    15: 'i860',
    18: 'powerpc',
    [0x01000012]: 'powerpc64',
  };

  const CPU_SUBTYPE_MASK = 0xff000000;

  // Subtype tables are keyed by cputype name, then by (subtype & ~mask).
  const CPU_SUBTYPE_NAMES = {
    i386: { 0: 'i386_all', 3: 'i386_all', 4: '486', 5: '586', 8: 'pentium_m5', 9: 'celeron', 10: 'pentium_pro', 11: 'pentium_4', 13: 'pentium_ii', 14: 'itanium', 15: 'xeon' },
    x86_64: { 0: 'x86_64_all', 3: 'x86_64_all', 4: 'x86_arch1', 8: 'x86_64_h (Haswell)' },
    arm: { 0: 'arm_all', 5: 'armv4t', 6: 'armv6', 7: 'armv5tej', 8: 'xscale', 9: 'armv7', 10: 'armv7f', 11: 'armv7s', 12: 'armv7k', 13: 'armv8', 14: 'armv6m', 15: 'armv7m', 16: 'armv7em', 17: 'armv8m' },
    arm64: { 0: 'arm64_all', 1: 'arm64v8', 2: 'arm64e' },
    arm64_32: { 0: 'arm64_32_all', 1: 'arm64_32_v8' },
    powerpc: { 0: 'powerpc_all', 1: '601', 3: '603', 4: '603e', 5: '603ev', 6: '604', 7: '604e', 8: '620', 9: '750', 10: '7400', 11: '7450', 100: '970' },
    powerpc64: { 0: 'powerpc_all', 100: '970' },
  };

  const MH_FILETYPE_NAMES = {
    1: 'MH_OBJECT (relocatable object)',
    2: 'MH_EXECUTE (executable)',
    3: 'MH_FVMLIB',
    4: 'MH_CORE (core dump)',
    5: 'MH_PRELOAD',
    6: 'MH_DYLIB (dynamic library)',
    7: 'MH_DYLINKER',
    8: 'MH_BUNDLE (loadable bundle/plugin)',
    9: 'MH_DYLIB_STUB',
    10: 'MH_DSYM (debug symbols)',
    11: 'MH_KEXT_BUNDLE (kernel extension)',
    12: 'MH_FILESET',
  };

  function cputypeName(cputype) {
    return CPU_TYPE_NAMES[cputype >>> 0] || null;
  }

  function cpusubtypeInfo(cputype, cpusubtypeRaw) {
    const capBits = cpusubtypeRaw & CPU_SUBTYPE_MASK;
    const bare = cpusubtypeRaw & ~CPU_SUBTYPE_MASK;
    const typeName = cputypeName(cputype);
    const table = typeName && CPU_SUBTYPE_NAMES[typeName];
    const name = table && bare in table ? table[bare] : null;
    return { name, capBits: capBits ? capBits >>> 0 : 0 };
  }

  // ---------------------------------------------------------------------
  // Thin (single-architecture) Mach-O header peek
  // ---------------------------------------------------------------------

  // Reads just enough of a thin Mach-O header (at byte offset `off` in
  // `view`) to report its own idea of cputype/cpusubtype/filetype, for
  // cross-checking against what a fat_arch entry claims. Never throws --
  // returns { error } instead, since this is a best-effort extra, not the
  // core thing this tool promises.
  function peekThinHeader(view, off, byteLength) {
    if (off + 4 > byteLength) return { error: 'Slice is too short to contain a Mach-O header' };
    const magicBE = view.getUint32(off, false);
    const magicLE = view.getUint32(off, true);
    let littleEndian, is64, magicHex;
    if (magicLE === MH_MAGIC) {
      littleEndian = true;
      is64 = false;
      magicHex = magicLE;
    } else if (magicLE === MH_MAGIC_64) {
      littleEndian = true;
      is64 = true;
      magicHex = magicLE;
    } else if (magicBE === MH_MAGIC) {
      littleEndian = false;
      is64 = false;
      magicHex = magicBE;
    } else if (magicBE === MH_MAGIC_64) {
      littleEndian = false;
      is64 = true;
      magicHex = magicBE;
    } else {
      return { error: `Slice does not start with a recognized thin Mach-O magic (found 0x${magicBE.toString(16).padStart(8, '0')})` };
    }
    const headerSize = is64 ? 32 : 28;
    if (off + headerSize > byteLength) return { error: 'Slice is too short to contain a complete Mach-O header' };
    const cputype = view.getInt32(off + 4, littleEndian);
    const cpusubtypeRaw = view.getInt32(off + 8, littleEndian);
    const filetype = view.getUint32(off + 12, littleEndian);
    const ncmds = view.getUint32(off + 16, littleEndian);
    const sizeofcmds = view.getUint32(off + 20, littleEndian);
    const flags = view.getUint32(off + 24, littleEndian);
    const sub = cpusubtypeInfo(cputype, cpusubtypeRaw);
    return {
      magicHex: `0x${magicHex.toString(16).padStart(8, '0')}`,
      is64,
      littleEndian,
      cputype,
      cputypeHex: `0x${(cputype >>> 0).toString(16).padStart(8, '0')}`,
      cputypeName: cputypeName(cputype),
      cpusubtype: cpusubtypeRaw,
      cpusubtypeName: sub.name,
      filetype,
      filetypeName: MH_FILETYPE_NAMES[filetype] || null,
      ncmds,
      sizeofcmds,
      flags,
    };
  }

  // ---------------------------------------------------------------------
  // Top-level entry point
  // ---------------------------------------------------------------------

  function parseMachO(buffer) {
    if (buffer.byteLength < 8) throw new MachOParseError('File is too small to contain even a Mach-O or fat header');
    const view = new DataView(buffer);
    const magicBE = view.getUint32(0, false);
    const magicLE = view.getUint32(0, true);

    if (magicBE === FAT_MAGIC || magicBE === FAT_MAGIC_64) {
      return parseFatBinary(buffer, view, magicBE === FAT_MAGIC_64);
    }
    if (magicBE === FAT_CIGAM || magicBE === FAT_CIGAM_64) {
      throw new MachOParseError('This file has a byte-swapped fat header, which no real Mach-O fat binary has ever shipped with. It is likely corrupted or not actually a Mach-O file.');
    }
    // Not fat -- is it a single-architecture (thin) Mach-O instead?
    if (magicLE === MH_MAGIC || magicLE === MH_MAGIC_64 || magicBE === MH_MAGIC || magicBE === MH_MAGIC_64) {
      const thin = peekThinHeader(view, 0, buffer.byteLength);
      return {
        isFat: false,
        isThinMachO: true,
        fileSize: buffer.byteLength,
        thin,
      };
    }
    throw new MachOParseError(
      `Not a Mach-O fat/universal binary or a single-architecture Mach-O file (first 4 bytes: 0x${magicBE.toString(16).padStart(8, '0')}). Expected the fat magic 0xcafebabe / 0xcafebabf, or a thin Mach-O magic 0xfeedface / 0xfeedfacf.`
    );
  }

  function parseFatBinary(buffer, view, is64BitOffsets) {
    const byteLength = buffer.byteLength;
    const nfatArch = view.getUint32(4, false);
    const archEntrySize = is64BitOffsets ? 32 : 20;
    const headerEnd = 8 + nfatArch * archEntrySize;
    if (headerEnd > byteLength) {
      throw new MachOParseError(`The fat header declares ${nfatArch} architecture(s), but the file is too short to hold that many fat_arch entries`);
    }

    const architectures = [];
    const warnings = [];
    let cursor = 8;
    for (let i = 0; i < nfatArch; i++) {
      let cputype, cpusubtypeRaw, offset, size, align;
      if (is64BitOffsets) {
        cputype = view.getInt32(cursor, false);
        cpusubtypeRaw = view.getInt32(cursor + 4, false);
        offset = Number(view.getBigUint64(cursor + 8, false));
        size = Number(view.getBigUint64(cursor + 16, false));
        align = view.getUint32(cursor + 24, false);
        cursor += 32;
      } else {
        cputype = view.getInt32(cursor, false);
        cpusubtypeRaw = view.getInt32(cursor + 4, false);
        offset = view.getUint32(cursor + 8, false);
        size = view.getUint32(cursor + 12, false);
        align = view.getUint32(cursor + 16, false);
        cursor += 20;
      }

      const sub = cpusubtypeInfo(cputype, cpusubtypeRaw);
      const entry = {
        index: i,
        cputype,
        cputypeHex: `0x${(cputype >>> 0).toString(16).padStart(8, '0')}`,
        cputypeName: cputypeName(cputype),
        cpusubtype: cpusubtypeRaw,
        cpusubtypeHex: `0x${(cpusubtypeRaw >>> 0).toString(16).padStart(8, '0')}`,
        cpusubtypeName: sub.name,
        cpusubtypeCapBits: sub.capBits,
        offset,
        size,
        align,
        alignBytes: 2 ** align,
      };

      if (offset + size > byteLength) {
        entry.warning = `Declared slice range [${offset}, ${offset + size}) runs past the end of the file (${byteLength} bytes)`;
        warnings.push(`Architecture #${i} (${entry.cputypeName || entry.cputypeHex}): ${entry.warning}`);
        entry.thin = null;
      } else {
        entry.thin = peekThinHeader(view, offset, byteLength);
        if (!entry.thin.error) {
          const mismatches = [];
          if (entry.thin.cputype !== cputype) mismatches.push(`cputype ${entry.thin.cputypeHex} in the slice's own header vs ${entry.cputypeHex} declared by the fat header`);
          if ((entry.thin.cpusubtype & ~CPU_SUBTYPE_MASK) !== (cpusubtypeRaw & ~CPU_SUBTYPE_MASK)) mismatches.push(`cpusubtype ${entry.thin.cpusubtype} in the slice's own header vs ${cpusubtypeRaw} declared by the fat header`);
          if (mismatches.length) {
            entry.thin.mismatchWarning = `This slice's own Mach-O header disagrees with the fat header: ${mismatches.join('; ')}.`;
            warnings.push(`Architecture #${i}: ${entry.thin.mismatchWarning}`);
          }
        }
      }

      architectures.push(entry);
    }

    return {
      isFat: true,
      is64BitOffsets,
      fileSize: byteLength,
      nfatArch,
      architectures,
      warnings,
    };
  }

  // Returns the raw bytes of one architecture slice, ready to be saved as
  // a standalone thin Mach-O file. Just a byte-range copy -- confirmed
  // against `llvm-lipo -thin` to be byte-for-byte what lipo itself
  // extracts, since fat binaries apply no compression or transformation.
  function extractSlice(buffer, archEntry) {
    if (archEntry.offset + archEntry.size > buffer.byteLength) {
      throw new MachOParseError('Cannot extract: the declared slice range runs past the end of the file');
    }
    return buffer.slice(archEntry.offset, archEntry.offset + archEntry.size);
  }

  function describeArch(entry) {
    return entry.cputypeName ? (entry.cpusubtypeName && entry.cpusubtypeName !== `${entry.cputypeName}_all` ? `${entry.cputypeName} (${entry.cpusubtypeName})` : entry.cputypeName) : entry.cputypeHex;
  }

  return {
    MachOParseError,
    parseMachO,
    extractSlice,
    describeArch,
    _internal: {
      FAT_MAGIC,
      FAT_MAGIC_64,
      MH_MAGIC,
      MH_MAGIC_64,
      cputypeName,
      cpusubtypeInfo,
      peekThinHeader,
      parseFatBinary,
      CPU_TYPE_NAMES,
      CPU_SUBTYPE_NAMES,
      MH_FILETYPE_NAMES,
    },
  };
});
