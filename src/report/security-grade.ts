import type { Report } from '../core/types.js';

export interface SecurityGrade {
  letter: 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  complete: boolean;
  rationale: string;
}

const WEIGHTS = { critical: 30, high: 12, medium: 5, low: 2, info: 0 } as const;

function letterFor(score: number): SecurityGrade['letter'] {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/** A transparent finding-density signal, not a certification or proof that the repository is secure. */
export function securityGrade(report: Report): SecurityGrade {
  const complete = !report.scanners.some((scanner) => scanner.incomplete);
  const deduction = Object.entries(WEIGHTS).reduce(
    (total, [severity, weight]) => total + report.summary[severity as keyof typeof WEIGHTS] * weight,
    0,
  );
  const uncapped = Math.max(0, 100 - deduction);
  const score = complete ? uncapped : Math.min(uncapped, 69);
  return {
    letter: letterFor(score),
    score,
    complete,
    rationale: complete
      ? 'Score starts at 100 and deducts 30/12/5/2 points for each critical/high/medium/low finding.'
      : 'Incomplete scanner coverage caps the score at 69; findings deduct 30/12/5/2 points by severity.',
  };
}
