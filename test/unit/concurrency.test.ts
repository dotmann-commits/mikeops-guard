import { describe, expect, it } from 'vitest';
import { mapLimit } from '../../src/core/concurrency.js';

const tick = () => new Promise((resolve) => setTimeout(resolve, 1));

describe('mapLimit', () => {
  it('never runs more than the limit at once and keeps input order', async () => {
    let active = 0;
    let peak = 0;
    const results = await mapLimit([...Array(50).keys()], 4, async (n) => {
      active++;
      peak = Math.max(peak, active);
      await tick();
      active--;
      return n * 2;
    });
    expect(peak).toBe(4);
    expect(results).toEqual([...Array(50).keys()].map((n) => n * 2));
  });

  it('handles empty input and rejects like Promise.all', async () => {
    expect(await mapLimit([], 3, () => Promise.resolve(1))).toEqual([]);
    await expect(mapLimit([1, 2, 3], 2, (n) => (n === 2 ? Promise.reject(new Error('boom')) : Promise.resolve(n)))).rejects.toThrow('boom');
  });

  it('rejects a limit that is not a positive integer', async () => {
    await expect(mapLimit([1], 0, () => Promise.resolve(1))).rejects.toThrow(RangeError);
  });
});
