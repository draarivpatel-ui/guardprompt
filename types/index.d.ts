/**
 * TypeScript definitions for guardprompt.
 */

export const VERSION: string;

export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_GUARDPROMPT_INVALID_INPUT';
  INVALID_OPTIONS: 'ERR_GUARDPROMPT_INVALID_OPTIONS';
  INPUT_TOO_LARGE: 'ERR_GUARDPROMPT_INPUT_TOO_LARGE';
  BLOCKED: 'ERR_GUARDPROMPT_BLOCKED';
}>;

export const DEFAULT_LIMITS: Readonly<{
  maxInputLength: number;
  maxDecodedSize: number;
  maxEncodedDepth: number;
  maxEncodedCandidates: number;
  maxFindings: number;
}>;

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Layer = 'core' | 'unicode' | 'injection' | 'encoding' | 'egress';
export type Action = 'allow' | 'warn' | 'block';
export type RiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface RuleMetadata {
  layer: Layer;
  severity: Severity;
  cwe: string;
  owasp: string;
}

export const RULES: Readonly<Record<string, Readonly<RuleMetadata>>>;

export interface GuardPromptOptions {
  /** Maximum UTF-16 input length accepted before inspection. Hard cap: 1000000. */
  maxInputLength?: number;
  /** Total decoded byte budget for recursive payload inspection. Hard cap: 262144. */
  maxDecodedSize?: number;
  /** Maximum recursive encoding depth. Hard cap: 5. */
  maxEncodedDepth?: number;
  /** Maximum encoded candidates inspected per scan. Hard cap: 128. */
  maxEncodedCandidates?: number;
  /** Maximum findings retained in a report. Hard cap: 1000. */
  maxFindings?: number;
  /** Replacement text used in safe-redacted output. */
  redactionToken?: string;
  /** Risk score at or above which action is warn. */
  warnThreshold?: number;
  /** Risk score at or above which action is block. Critical findings always block. */
  blockThreshold?: number;
  /** Decode bounded base64, hexadecimal, URL-encoded, and ROT13 payload shapes. */
  decodeEncoded?: boolean;
  /** Run encoded-payload inspection during inspectPrompt. */
  scanEncoded?: boolean;
  /** Apply Unicode NFKC before canonical stripping. */
  normalizeUnicode?: boolean;
  /** Exact canary strings that must never appear in output. */
  canaryTokens?: string[];
  /** Exact caller-supplied phrases treated as injection findings. */
  additionalPhrases?: string[];
  /** Hostnames whose Markdown images are trusted by the egress scanner. */
  trustedImageHosts?: string[];
  /** Include the canonical string in reports. Redacted output is always included. */
  includeCanonical?: boolean;
}

export interface Finding {
  id: string;
  layer: Layer;
  severity: Severity;
  cwe: string;
  owasp: string;
  description: string;
  evidence: string;
  /** UTF-16 start offset in the scanned canonical text, or -1 for nested/decoded evidence. */
  start: number;
  /** UTF-16 end offset in the scanned canonical text, or -1 for nested/decoded evidence. */
  end: number;
  /** Encoding path such as ['base64', 'url'] when the finding came from a decoded payload. */
  path?: string[];
  /** Original nested rule id when this finding is a projected nested result. */
  nestedRule?: string;
  /** Count for aggregate Unicode findings. */
  count?: number;
  /** Decoded length for encoding findings. */
  decodedLength?: number;
  /** Script names for mixed-script findings. */
  scripts?: string[];
  /** Decoded Unicode Tag preview for tag findings. */
  decoded?: string;
}

export interface UnicodeStats {
  tags: number;
  bidi: number;
  zeroWidth: number;
  variationSelectors: number;
  controls: number;
  confusables: number;
  inputLength: number;
  canonicalLength: number;
}

export interface HiddenSegment {
  text: string;
  start: number;
  end: number;
  length: number;
}

export interface UnicodeScanResult {
  canonical: string;
  findings: readonly Finding[];
  hiddenSegments: readonly HiddenSegment[];
  stats: Readonly<UnicodeStats>;
}

export interface EncodedPayload {
  encoding: 'base64' | 'hex' | 'url';
  path: readonly string[];
  depth: number;
  start: number;
  end: number;
  length: number;
  preview: string;
}

export interface EncodedScanResult {
  findings: readonly Finding[];
  payloads: readonly EncodedPayload[];
  stats: Readonly<{
    candidates: number;
    decodedBytes: number;
    depth: number;
  }>;
}

export interface InspectionStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface InspectionReport {
  kind: 'input' | 'output';
  action: Action;
  riskScore: number;
  riskLevel: RiskLevel;
  inputLength: number;
  canonicalLength: number;
  findings: readonly Finding[];
  findingCount: number;
  truncated: boolean;
  redacted: string;
  canonical?: string;
  stats: Readonly<InspectionStats>;
  unicode?: Readonly<UnicodeStats>;
  hiddenSegmentCount?: number;
}

export class GuardPromptError extends Error {
  readonly name: 'GuardPromptError';
  readonly code: string;
  readonly reason: string;
  readonly input?: unknown;
  readonly findings?: readonly Finding[];
  constructor(code: string, reason: string, input?: unknown, findings?: readonly Finding[], cause?: unknown);
  toJSON(): Record<string, unknown>;
}

export function normalizeOptions(options?: GuardPromptOptions): Readonly<Required<GuardPromptOptions>>;

export function scanUnicode(input: string, options?: GuardPromptOptions): UnicodeScanResult;
export function scanInjection(input: string, options?: GuardPromptOptions): readonly Finding[];
export function scanEncoded(input: string, options?: GuardPromptOptions): EncodedScanResult;
export function scanEgress(output: string, options?: GuardPromptOptions): readonly Finding[];

export function inspectPrompt(input: string, options?: GuardPromptOptions): InspectionReport;
export function inspectOutput(output: string, options?: GuardPromptOptions): InspectionReport;
export function sanitizePrompt(input: string, options?: GuardPromptOptions): string;
export function sanitizeOutput(output: string, options?: GuardPromptOptions): string;
export function assertSafePrompt(input: string, options?: GuardPromptOptions): InspectionReport;
export function assertSafeOutput(output: string, options?: GuardPromptOptions): InspectionReport;

export interface PromptFirewall {
  inspectPrompt(input: string, overrides?: GuardPromptOptions): InspectionReport;
  inspectOutput(output: string, overrides?: GuardPromptOptions): InspectionReport;
  sanitizePrompt(input: string, overrides?: GuardPromptOptions): string;
  sanitizeOutput(output: string, overrides?: GuardPromptOptions): string;
  assertSafePrompt(input: string, overrides?: GuardPromptOptions): InspectionReport;
  assertSafeOutput(output: string, overrides?: GuardPromptOptions): InspectionReport;
  scanUnicode(input: string, overrides?: GuardPromptOptions): UnicodeScanResult;
  scanInjection(input: string, overrides?: GuardPromptOptions): readonly Finding[];
  scanEncoded(input: string, overrides?: GuardPromptOptions): EncodedScanResult;
  scanEgress(output: string, overrides?: GuardPromptOptions): readonly Finding[];
}

export function createPromptFirewall(options?: GuardPromptOptions): PromptFirewall;

declare const guardprompt: {
  VERSION: typeof VERSION;
  CODE: typeof CODE;
  DEFAULT_LIMITS: typeof DEFAULT_LIMITS;
  RULES: typeof RULES;
  GuardPromptError: typeof GuardPromptError;
  normalizeOptions: typeof normalizeOptions;
  scanUnicode: typeof scanUnicode;
  scanInjection: typeof scanInjection;
  scanEncoded: typeof scanEncoded;
  scanEgress: typeof scanEgress;
  inspectPrompt: typeof inspectPrompt;
  inspectOutput: typeof inspectOutput;
  sanitizePrompt: typeof sanitizePrompt;
  sanitizeOutput: typeof sanitizeOutput;
  assertSafePrompt: typeof assertSafePrompt;
  assertSafeOutput: typeof assertSafeOutput;
  createPromptFirewall: typeof createPromptFirewall;
};

export default guardprompt;
