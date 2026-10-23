#!/usr/bin/env bash
# Turns an encrypted PSP EBOOT.BIN into a plain ELF: scripts/decrypt.sh <EBOOT.BIN> <out.ELF>
# An EBOOT that is already an ELF is copied as is.  Otherwise the tool named by
# $PSP_DECRYPT (falling back to tools/deceboot/deceboot) decrypts it.
#
# PSP_DECRYPT may be an executable or a *directory* holding the decrypter. A
# decrypted file must be written to a script-specific path, but the two common
# tools differ in how they write one:
#   pspdecrypt <in> [--outfile=FILE]   (--outfile must stick to the input name)
#   DecEboot   <in> <out>
set -euo pipefail
source "$(dirname "$0")/common.sh"
in="$1"; out="$2"
if [ "$(head -c 4 "$in" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; then
  cp "$in" "$out"
  exit 0
fi

# Accept a directory as well as a binary, so a checkout of either tool works.
for name in pspdecrypt deceboot; do
  if [ -d "$PSP_DECRYPT" ] && [ -x "$PSP_DECRYPT/$name" ]; then
    PSP_DECRYPT="$PSP_DECRYPT/$name"
    break
  fi
done

if [ -x "$PSP_DECRYPT" ]; then
  tool="$PSP_DECRYPT"
  case "$(basename "$tool")" in
    # pspdecrypt refuses to put --outfile somewhere other than next to the
    # input, so decrypt in a scratch directory beside $in and copy the result.
    *pspdecrypt*)
      dir="$(cd "$(dirname "$in")" && pwd)/.pspdecrypt.$$"
      rm -rf "$dir"; mkdir -p "$dir"
      trap 'rm -rf "$dir"' EXIT
      "$tool" "$in" --outfile="$dir/EBOOT.ELF"
      cp "$dir/EBOOT.ELF" "$out"
      ;;
    *)
      "$tool" "$in" "$out"
      ;;
  esac
else
  fallback="$ROOT/tools/deceboot/deceboot"
  if [ -x "$fallback" ]; then
    "$fallback" "$in" "$out"
  else
    echo "The EBOOT is encrypted and no decrypter was found." >&2
    echo "Point PSP_DECRYPT at DecEboot, pspdecrypt, or a directory holding either, or" >&2
    echo "dump a decrypted EBOOT with PPSSPP (Settings > Tools > Developer tools)." >&2
    exit 1
  fi
fi
