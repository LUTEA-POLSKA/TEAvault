/**
 * Name-based category suggestion.
 *
 * ## Purpose and boundary
 *
 * TEAvault lets the user group keys into categories (free text, not an enum).
 * This helper suggests one based on the *variable name* — nothing else. The
 * suggestion is advisory: it is shown next to an empty category field so the
 * user can keep it or type over it. It never overrides a manual choice, never
 * reads a secret value, and returns `null` when nothing is obvious. An
 * ambiguous name gets no suggestion at all rather than a wrong one.
 *
 * The categories here are what real key names look like; out of agreement the
 * only cost is a suggestion the user can dismiss.
 *
 * Matching is case-insensitive but token-based on underscore boundaries, so
 * `OPENAI_API_KEY` hits the table while `OPENAI` might not — a bare vendor name
 * tells us nothing about the key's job.
 */

const RULES: Array<{ tokens: string[]; category: string }> = [
  { tokens: ['OPENAI', 'OAI', 'ANTHROPIC', 'CLAUDE', 'GROQ', 'GEMINI', 'GOOGLE'], category: 'llm' },
  { tokens: ['GITHUB', 'GH', 'GITLAB', 'GL'], category: 'ci' },
  { tokens: ['CLOUDFLARE', 'CF', 'R2'], category: 'infra' },
  { tokens: ['AWS', 'S3', 'AMAZON', 'AZURE'], category: 'storage' },
  { tokens: ['SENTRY', 'DATADOG', 'GRAFANA', 'PROMETHEUS'], category: 'monitoring' },
  { tokens: ['AUTH0', 'CLERK', 'FIREBASE', 'ZITADEL'], category: 'auth' },
  { tokens: ['TAVILY', 'BRAVE', 'ALGOLIA'], category: 'search' },
]

export function suggestCategory(name: string): string | null {
  const upper = name.toUpperCase()
  const tokens = upper.split(/[^A-Z0-9]+/).filter((t) => t.length > 0)
  if (tokens.length === 0) return null

  let hit: string | null = null
  for (const { tokens: wanted, category } of RULES) {
    // A key like OPENAI_API_KEY or ANTHROPIC_ORG gets its category; a generic
    // name shares no token with the table and returns nothing.
    const covered = wanted.some((w) => tokens.includes(w))
    if (!covered) continue
    // Two rules matching is ambiguous — no suggestion is safer than a guess.
    if (hit !== null && hit !== category) return null
    hit = category
  }
  return hit
}