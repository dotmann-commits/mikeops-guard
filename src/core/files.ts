import { open } from 'node:fs/promises';

/** Hand-written config and source is kilobytes. Anything larger is generated or hostile, and not worth holding in memory. */
export const MAX_TEXT_FILE_BYTES = 1024 * 1024;

export type ReadTextResult = { ok: true; text: string } | { ok: false; reason: string };

/**
 * Reads at most maxBytes from a file in the scanned repository. It reads from the open handle instead of trusting a
 * prior stat, so a file that grows (or a FIFO) can never push memory past the limit.
 */
export async function readTextFile(absolutePath: string, maxBytes = MAX_TEXT_FILE_BYTES): Promise<ReadTextResult> {
  const handle = await open(absolutePath, 'r');
  try {
    const buffer = Buffer.alloc(maxBytes + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    if (total > maxBytes) return { ok: false, reason: `larger than ${formatBytes(maxBytes)}` };
    return { ok: true, text: buffer.subarray(0, total).toString('utf8') };
  } finally {
    await handle.close();
  }
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${Math.round(bytes / (1024 * 1024))} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}
