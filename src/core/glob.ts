/**
 * Minimal glob matcher for exclude and ignore patterns.
 * Supports "**" (any depth), "*" (within one segment) and "?" (one character).
 */
export function globToRegExp(pattern: string): RegExp {
  let source = '';
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern.charAt(i);
    if (char === '*' && pattern[i + 1] === '*') {
      if (pattern[i + 2] === '/') {
        source += '(?:.*/)?';
        i += 2;
      } else {
        source += '.*';
        i += 1;
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${source}$`);
}

export interface PathMatcher {
  (relativePath: string): boolean;
}

export function createMatcher(patterns: readonly string[]): PathMatcher {
  const regexes = patterns.map(globToRegExp);
  return (relativePath) => {
    const normalized = toPosix(relativePath);
    return regexes.some((re) => re.test(normalized));
  };
}

export function toPosix(p: string): string {
  return p.replaceAll('\\', '/').replace(/^\.\//, '');
}
