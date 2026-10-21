// C0 controls except tab and newline, DEL, C1 controls (which include CSI), and Unicode bidi overrides.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g;

/**
 * Text from scanners, the scanned repository or a language model must not drive the terminal: an escape sequence
 * could clear the screen, hide findings or fake a verdict. Unsafe characters are removed before printing.
 */
export function terminalSafe(value: string): string {
  return value.replace(UNSAFE, '');
}
