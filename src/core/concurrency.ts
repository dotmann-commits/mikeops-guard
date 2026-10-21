/** Default for file work: enough to hide disk latency, far below the open-file limit of any OS. */
export const FILE_CONCURRENCY = 32;

/**
 * Like Promise.all over items.map(fn), but with at most `limit` calls in flight.
 * Results keep the input order. The first rejection rejects the whole call, as Promise.all does.
 */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError('limit must be a positive integer');
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index] as T, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
