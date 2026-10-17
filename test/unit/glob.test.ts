import { describe, expect, it } from 'vitest';
import { createMatcher, globToRegExp } from '../../src/core/glob.js';

describe('globToRegExp', () => {
  it.each([
    ['**/node_modules/**', 'node_modules/', true],
    ['**/node_modules/**', 'a/b/node_modules/x/y.js', true],
    ['**/node_modules/**', 'node_modules_old/x', false],
    ['*.yml', 'a.yml', true],
    ['*.yml', 'dir/a.yml', false],
    ['docker/**', 'docker/a/Dockerfile', true],
    ['file?.txt', 'file1.txt', true],
    ['a.b', 'axb', false],
  ])('%s matches %s: %s', (pattern, input, expected) => {
    expect(globToRegExp(pattern).test(input)).toBe(expected);
  });

  it('normalises Windows separators and leading ./', () => {
    const matches = createMatcher(['vendor/**']);
    expect(matches('.\\vendor\\lib.js')).toBe(true);
  });
});
