export type WireFormat = 'openai' | 'anthropic' | 'gemini';

export interface VirtualKey {
  id: string;
  key: string;
  name: string;
  owner: string;
  tag: string;
  allowedModels: string[]; // ['*'] or list of model IDs / aliases / routes
  allowedProviders: string[]; // [] = no provider restriction (FR-12.19)
  rpmLimit: number;
  tpmLimit: number;
  dailyBudget: number; // USD
  monthlyBudget: number; // USD
  currentDailySpend: number;
  currentMonthlySpend: number;
  createdAt: string;
  expiresAt: string | null;
  status: 'active' | 'disabled' | 'revoked';
  allowedIps?: string[];
  totalRequests: number;
  totalTokens: number;
}

export interface Provider {
  id: string;
  name: string;
  baseUrl: string;
  wireFormat: WireFormat;
  authScheme: 'bearer' | 'custom_header' | 'query_param';
  customHeaderName?: string;
  customParamName?: string;
  status: 'healthy' | 'degraded' | 'error';
  modelsCount: number;
  accountsCount: number;
  extraHeaders?: Record<string, string>;
  modelsPath?: string;
  timeoutMs: number;
  capabilityMode: 'permissive' | 'strict';
  followRedirects?: boolean;
  credentialHosts?: string;
  allowInsecureTls?: boolean;
  wirePlugin?: string;
  credentialPlugin?: string;
  modelSourcePlugin?: string;
  /** Write-only: a credential supplied when adding/editing (never returned by the API). */
  apiKey?: string;
  accountLabel?: string;
  lastPingMs: number;
}

export interface Account {
  id: string;
  providerId: string;
  providerName: string;
  label: string;
  keyMasked: string;
  status: 'healthy' | 'cooldown' | 'exhausted' | 'disabled';
  cooldownUntil?: string | null;
  quotaResetTime?: string | null;
  quotaType: 'daily' | 'monthly' | 'none';
  softQuotaSpendLimit?: number;
  currentSpend: number;
  requestsCount: number;
  tokensCount: number;
  priority: number;
  lastError?: string;
}

export interface ModelCapability {
  text: boolean;
  vision: boolean;
  reasoning: boolean;
  toolCalling: boolean;
  audio: boolean;
}

export interface ModelPrice {
  inputPer1M: number;
  outputPer1M: number;
  cachedPer1M: number;
  thinkingPer1M: number;
}

export interface ModelConfig {
  id: string;
  providerId: string;
  providerName: string;
  upstreamModelId: string;
  displayName: string;
  enabled: boolean;
  contextWindow: number;
  maxOutputTokens: number;
  capabilities: ModelCapability;
  prices: ModelPrice;
  parameters: {
    temperature?: { supported: boolean; min: number; max: number; default: number; policy: 'forward' | 'clamp' | 'reject' };
    top_p?: { supported: boolean; min: number; max: number; default: number; policy: 'forward' | 'clamp' | 'reject' };
    top_k?: { supported: boolean; min: number; max: number; default: number; policy: 'forward' | 'clamp' | 'reject' };
  };
  thinkingMap: {
    scale: 'off' | 'low' | 'medium' | 'high' | 'custom';
    budgetTokens?: number;
    mappedField: string;
  };
}

export interface RouteTarget {
  id: string;
  accountId: string;
  accountLabel: string;
  providerName: string;
  modelId: string;
  modelDisplayName: string;
  priority: number;
  weight?: number;
}

export interface Route {
  id: string;
  name: string;
  description: string;
  selectionStrategy: 'priority' | 'round-robin' | 'weighted' | 'least-used';
  fallbackTriggers: {
    on429: boolean;
    onQuota: boolean;
    on5xx: boolean;
    onTimeout: boolean;
  };
  targets: RouteTarget[];
  continuityPolicy: 'strip' | 'convert' | 'error';
  portabilityPolicy: 'reject' | 'strip_with_warning';
  cacheAffinity: boolean;
  stickyRouting: boolean;
  totalHops: number;
  status: 'active' | 'degraded' | 'all_exhausted';
}

export interface ModelAlias {
  id: string;
  aliasName: string;
  targetType: 'model' | 'route';
  targetId: string;
  targetDisplayName: string;
  description: string;
}

export interface RequestLog {
  id: string;
  requestId: string;
  timestamp: string;
  virtualKeyId: string;
  virtualKeyName: string;
  clientFormat: 'openai' | 'anthropic';
  requestedModel: string;
  effectiveTarget: string;
  routeName?: string;
  fallbackHops: number;
  fallbackPath: string[];
  status: 'success' | 'rate_limited' | 'quota_exhausted' | 'fallback_recovered' | 'client_error' | 'upstream_error';
  statusCode: number;
  latencyMs: number;
  ttftMs: number;
  inputTokens: number;
  outputTokens: number;
  cachedTokens: number;
  thinkingTokens: number;
  costUsd: number;
  cacheStatus: 'hit' | 'miss' | 'bypass';
  servingAccount: string;
  servingProvider: string;
  opaqueRouteId: string;
  usageConfidence: 'provider_reported' | 'estimated' | 'unknown';
  commitState: string;
  retryCount: number;
  promptPreview: string;
  responsePreview: string;
}

export interface LiveRequest {
  requestId: string;
  keyName?: string | null;
  frontend: string;
  requestedModel: string;
  routeName?: string | null;
  phase: 'selecting' | 'streaming' | 'committed' | 'done';
  commitState: string;
  fallbackHops: number;
  retryCount: number;
  inputTokens?: number | null;
  outputTokens?: number | null;
  status: string;
  latencyMs: number;
  ttftMs?: number | null;
  finished: boolean;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  targetType: 'key' | 'provider' | 'account' | 'route' | 'alias' | 'model' | 'system';
  targetId: string;
  targetName: string;
  details: string;
}

export interface ProxyMetrics {
  activeStreams: number;
  totalRequests: number;
  totalTokens: number;
  totalSpendUsd: number;
  cacheHitRatio: number;
  fallbackRate: number;
  p50LatencyMs: number;
  p99LatencyMs: number;
  tunnelStatus: 'connected' | 'reconnecting' | 'error';
}
