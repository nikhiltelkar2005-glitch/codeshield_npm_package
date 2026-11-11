export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const aLen = a.length;
  const bLen = b.length;
  if (aLen === 0) return bLen;
  if (bLen === 0) return aLen;

  const d: number[][] = [];
  for (let i = 0; i <= aLen; i++) {
    d[i] = new Array<number>(bLen + 1).fill(0);
    d[i]![0] = i;
  }
  for (let j = 0; j <= bLen; j++) {
    d[0]![j] = j;
  }

  for (let i = 1; i <= aLen; i++) {
    for (let j = 1; j <= bLen; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const deletion = d[i - 1]![j]! + 1;
      const insertion = d[i]![j - 1]! + 1;
      const substitution = d[i - 1]![j - 1]! + cost;

      let min = Math.min(deletion, insertion, substitution);

      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        const transposition = d[i - 2]![j - 2]! + 1;
        if (transposition < min) min = transposition;
      }

      d[i]![j] = min;
    }
  }

  return d[aLen]![bLen]!;
}
