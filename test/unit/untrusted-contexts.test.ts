import { describe, expect, it } from 'vitest';
import { findUntrustedExpressions } from '../../src/scanners/workflow-audit/rules/untrusted-contexts.js';

describe('untrusted expression locations', () => {
  it.each(['\n', '\r\n'])('preserves zero-based lines with %j line endings', (newline) => {
    const script = [
      '${{ github.head_ref }} ${{ github.event.issue.title }}',
      '',
      '${{ github.sha }}',
      '${{',
      '  github.event.comment.body',
      '}}',
      '${{',
      '  github.sha',
      '}}',
      '${{ github.event.commits[0].message }}',
      '${{ github.sha }}',
    ].join(newline);

    expect(findUntrustedExpressions(script)).toEqual([
      { expression: '${{ github.head_ref }}', lineIndex: 0 },
      { expression: '${{ github.event.issue.title }}', lineIndex: 0 },
      { expression: ['${{', '  github.event.comment.body', '}}'].join(newline), lineIndex: 3 },
      { expression: '${{ github.event.commits[0].message }}', lineIndex: 9 },
    ]);
  });

  it('resets line state for each script', () => {
    const expression = '${{ github.head_ref }}';
    expect(findUntrustedExpressions('\n'.repeat(10) + expression)).toEqual([{ expression, lineIndex: 10 }]);
    expect(findUntrustedExpressions(expression)).toEqual([{ expression, lineIndex: 0 }]);
  });

  it('reports no hits for empty scripts or trusted expressions', () => {
    expect(findUntrustedExpressions('')).toEqual([]);
    expect(findUntrustedExpressions('${{ github.sha }}\n\n${{ runner.os }}')).toEqual([]);
  });

  it('keeps every location and source order across many expressions', () => {
    const expression = '${{ github.head_ref }}';
    const script = (expression + '\n${{ github.sha }}\n').repeat(1000);

    expect(findUntrustedExpressions(script)).toEqual(
      Array.from({ length: 1000 }, (_, index) => ({ expression, lineIndex: index * 2 })),
    );
  });
});
