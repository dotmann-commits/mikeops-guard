/**
 * Contexts an outside contributor can control, based on the GitHub Security Lab list.
 * Array segments may be written as [0], [*] or .*.
 */
const ITEM = String.raw`(?:\[[^\]]*\]|\.\*)`;
const UNTRUSTED_PATTERNS = [
  String.raw`github\.event\.(?:issue|pull_request|discussion)\.(?:title|body)`,
  String.raw`github\.event\.(?:comment|review|review_comment)\.body`,
  String.raw`github\.event\.pages${ITEM}?\.page_name`,
  String.raw`github\.event\.commits${ITEM}?\.(?:message|author\.(?:email|name))`,
  String.raw`github\.event\.head_commit\.(?:message|author\.(?:email|name))`,
  String.raw`github\.event\.pull_request\.head\.(?:ref|label|repo\.default_branch)`,
  String.raw`github\.event\.workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))`,
  String.raw`github\.head_ref`,
];

const UNTRUSTED = new RegExp(String.raw`\b(?:${UNTRUSTED_PATTERNS.join('|')})\b`);
const EXPRESSION = /\$\{\{([\s\S]*?)\}\}/g;

export interface UntrustedUse {
  expression: string;
  lineIndex: number;
}

/** Finds ${{ }} expressions that interpolate attacker-controlled data into a script. */
export function findUntrustedExpressions(script: string): UntrustedUse[] {
  const hits: UntrustedUse[] = [];
  for (const match of script.matchAll(EXPRESSION)) {
    const inner = match[1] ?? '';
    if (!UNTRUSTED.test(inner)) continue;
    const lineIndex = script.slice(0, match.index).split('\n').length - 1;
    hits.push({ expression: match[0], lineIndex });
  }
  return hits;
}

export function isUntrustedContext(expression: string): boolean {
  return UNTRUSTED.test(expression);
}
