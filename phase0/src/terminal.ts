/**
 * Render untrusted terminal text as one deterministic quoted line.
 *
 * The encoding is deliberately locale-independent. It escapes JSON-significant
 * punctuation plus C0/C1 controls, ANSI controls, bidi controls, line separators,
 * and unpaired UTF-16 surrogates. Valid surrogate pairs remain readable.
 */
export function quoteTerminalText(value: string): string {
  let quoted = '"';
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit === 0x22) {
      quoted += '\\"';
    } else if (codeUnit === 0x5c) {
      quoted += "\\\\";
    } else if (
      codeUnit <= 0x1f
      || (codeUnit >= 0x7f && codeUnit <= 0x9f)
      || codeUnit === 0x061c
      || codeUnit === 0x200e
      || codeUnit === 0x200f
      || (codeUnit >= 0x2028 && codeUnit <= 0x202e)
      || (codeUnit >= 0x2066 && codeUnit <= 0x206f)
      || (codeUnit >= 0xd800 && codeUnit <= 0xdfff
        && !(codeUnit <= 0xdbff
          && index + 1 < value.length
          && value.charCodeAt(index + 1) >= 0xdc00
          && value.charCodeAt(index + 1) <= 0xdfff))
    ) {
      quoted += `\\u${codeUnit.toString(16).padStart(4, "0")}`;
    } else {
      quoted += value[index];
      if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
        index += 1;
        quoted += value[index];
      }
    }
  }
  return `${quoted}"`;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return String(error);
  } catch {
    return "Unknown command failure";
  }
}

export function renderTopLevelError(error: unknown): string {
  return `✗ ${quoteTerminalText(errorMessage(error))}`;
}
