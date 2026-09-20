import React, { useState } from 'react';
import { Server, Plus, RefreshCw, CheckCircle2, Globe, Cpu, Sliders, ExternalLink, HelpCircle, Trash2, X, Pencil } from 'lucide-react';
import { Provider, ModelConfig } from '../../types';
import { WobblyCard, SketchButton, SketchBadge } from '../HandDrawnElements';
import { DESIGN_TOKENS } from '../../lib/designSystem';
import { Kinetix, DiscoveredModel } from '../../lib/resources';

/**
 * Fallback token metadata used when an upstream does not declare a context
 * window / max output. Applied both as the model form's initial values and as
 * the final fallback when creating, importing, or rendering a model, so an
 * "unknown" value never round-trips as 0.
 */
const DEFAULT_CONTEXT_WINDOW = 200000;
const DEFAULT_MAX_OUTPUT = 8192;

interface ProvidersViewProps {
  providers: Provider[];
  models: ModelConfig[];
  onAddProvider: (provider: Provider) => Promise<void> | void;
  onUpdateProvider: (providerId: string, provider: Provider) => Promise<void>;
  onAddModel: (model: ModelConfig) => void;
  onUpdateModel: (model: ModelConfig) => void;
  onDeleteModel: (modelId: string) => void;
  onDeleteProvider: (providerId: string) => void;
  onRefresh?: () => void;
}

export const ProvidersView: React.FC<ProvidersViewProps> = ({
  providers,
  models,
  onAddProvider,
  onUpdateProvider,
  onAddModel,
  onUpdateModel,
  onDeleteModel,
  onDeleteProvider,
  onRefresh,
}) => {
  const [selectedProviderId, setSelectedProviderId] = useState<string>(providers[0]?.id || '');
  const [showAddProviderModal, setShowAddProviderModal] = useState(false);
  const [showAddModelModal, setShowAddModelModal] = useState(false);
  const [confirmDeleteModelId, setConfirmDeleteModelId] = useState<string | null>(null);
  const [confirmDeleteProviderId, setConfirmDeleteProviderId] = useState<string | null>(null);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryResults, setDiscoveryResults] = useState<DiscoveredModel[] | null>(null);
  const [discoverySearch, setDiscoverySearch] = useState('');
  const [pingStatus, setPingStatus] = useState<Record<string, { ok: boolean; pingMs: number; error?: string }>>({});

  // New Provider Form State
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [wireFormat, setWireFormat] = useState<'gemini' | 'openai' | 'anthropic' | 'plugin'>('gemini');
  const [authScheme, setAuthScheme] = useState<'bearer' | 'custom_header' | 'query_param'>('bearer');
  const [customHeader, setCustomHeader] = useState('');
  const [customParam, setCustomParam] = useState('');
  const [modelsPath, setModelsPath] = useState('/models');
  const [extraHeaders, setExtraHeaders] = useState('');
  const [credentialHosts, setCredentialHosts] = useState('');
  const [followRedirects, setFollowRedirects] = useState(false);
  const [allowInsecureTls, setAllowInsecureTls] = useState(false);
  const [wirePlugin, setWirePlugin] = useState('');
  const [credentialPlugin, setCredentialPlugin] = useState('');
  const [modelSourcePlugin, setModelSourcePlugin] = useState('');
  const [timeoutMs, setTimeoutMs] = useState(120000);
  const [capabilityMode, setCapabilityMode] = useState<'permissive' | 'strict'>('permissive');
  const [apiKey, setApiKey] = useState('');
  const [accountLabel, setAccountLabel] = useState('');
  const [validation, setValidation] = useState<{ valid: boolean; problems: string[]; warnings: string[] } | null>(null);
  const [validating, setValidating] = useState(false);
  const [editingProviderId, setEditingProviderId] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  /** Parse a "Header: value" per line textarea into an object. */
  const parseHeaders = (text: string): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const line of text.split('\n')) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k) out[k] = v;
      }
    }
    return out;
  };

  // New Custom Model Form State
  const [modelUpstreamId, setModelUpstreamId] = useState('');
  const [modelDisplayName, setModelDisplayName] = useState('');
  const [modelContextWindow, setModelContextWindow] = useState(DEFAULT_CONTEXT_WINDOW);
  const [modelMaxOutput, setModelMaxOutput] = useState(DEFAULT_MAX_OUTPUT);
  const [modelInputPrice, setModelInputPrice] = useState(1.0);
  const [modelOutputPrice, setModelOutputPrice] = useState(4.0);
  const [capText, setCapText] = useState(true);
  const [capVision, setCapVision] = useState(true);
  const [capReasoning, setCapReasoning] = useState(false);
  const [capTools, setCapTools] = useState(true);
  const [modelValidation, setModelValidation] = useState<{ valid: boolean; problems: string[]; warnings: string[] } | null>(null);
  const [validatingModel, setValidatingModel] = useState(false);
  const [editingModelId, setEditingModelId] = useState<string | null>(null);

  const activeProvider = providers.find((p) => p.id === selectedProviderId) || providers[0];
  const providerModels = models.filter((m) => m.providerId === activeProvider?.id);

  // Fuzzy search over the discovered model list: case-insensitive, and every
  // whitespace-separated term must match as a subsequence of the model id.
  const discoveryMatches = (id: string, query: string) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    const terms = q.split(/\s+/).filter(Boolean);
    return terms.every((term) => {
      const hay = id.toLowerCase();
      if (hay.includes(term)) return true;
      // subsequence match (typo/skip friendly)
      let i = 0;
      for (const ch of hay) {
        if (ch === term[i]) i++;
        if (i === term.length) return true;
      }
      return false;
    });
  };
  const filteredDiscovery = (discoveryResults ?? []).filter((m) =>
    discoveryMatches(m.id, discoverySearch),
  );

  const handleTestPing = async (providerId: string) => {
    const firstModel = models.find((m) => m.providerId === providerId)?.upstreamModelId;
    try {
      const r = await Kinetix.test(providerId, firstModel || 'test');
      setPingStatus((prev) => ({
        ...prev,
        [providerId]: { ok: r.ok, pingMs: r.latency_ms ?? 0, error: r.error },
      }));
    } catch (e) {
      setPingStatus((prev) => ({
        ...prev,
        [providerId]: { ok: false, pingMs: 0, error: e instanceof Error ? e.message : String(e) },
      }));
    }
  };

  const handleFetchModelsDiscovery = async () => {
    if (!activeProvider) return;
    setIsDiscovering(true);
    setDiscoveryResults(null);
    setDiscoverySearch('');
    try {
      const found = await Kinetix.discover(activeProvider.id);
      setDiscoveryResults(found);
    } catch (e) {
      setDiscoveryResults([]);
      setPingStatus((prev) => ({
        ...prev,
        [activeProvider.id]: {
          ok: false,
          pingMs: 0,
          error: e instanceof Error ? e.message : String(e),
        },
      }));
    } finally {
      setIsDiscovering(false);
    }
  };

  const handleImportDiscoveredModel = (m: DiscoveredModel) => {
    const newModel: ModelConfig = {
      id: '',
      providerId: activeProvider.id,
      providerName: activeProvider.name,
      upstreamModelId: m.id,
      displayName: m.display_name || m.id,
      enabled: true,
      contextWindow: m.context_window ?? DEFAULT_CONTEXT_WINDOW,
      maxOutputTokens: m.max_output_tokens ?? DEFAULT_MAX_OUTPUT,
      capabilities: {
        text: true,
        vision: false,
        reasoning: m.id.includes('pro') || m.id.includes('thinking'),
        toolCalling: true,
        audio: false,
      },
      prices: {
        inputPer1M: 0,
        outputPer1M: 0,
        cachedPer1M: 0,
        thinkingPer1M: 0,
      },
      parameters: {},
      thinkingMap: { scale: 'off', mappedField: '' },
    };

    onAddModel(newModel);
    setDiscoveryResults((prev) => prev?.filter((x) => x.id !== m.id) || null);
  };

  const headersToText = (h?: Record<string, string>): string =>
    h ? Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n') : '';

  const resetProviderForm = () => {
    setEditingProviderId(null);
    setName('');
    setBaseUrl('');
    setWireFormat('gemini');
    setAuthScheme('bearer');
    setCustomHeader('');
    setCustomParam('');
    setModelsPath('/models');
    setExtraHeaders('');
    setCredentialHosts('');
    setFollowRedirects(false);
    setAllowInsecureTls(false);
    setWirePlugin('');
    setCredentialPlugin('');
    setModelSourcePlugin('');
    setTimeoutMs(120000);
    setCapabilityMode('permissive');
    setApiKey('');
    setAccountLabel('');
    setValidation(null);
  };

  const openEditProvider = (p: Provider) => {
    setEditingProviderId(p.id);
    setName(p.name);
    setBaseUrl(p.baseUrl);
    setWireFormat(p.wireFormat);
    setAuthScheme(p.authScheme);
    setCustomHeader(p.customHeaderName || '');
    setCustomParam(p.customParamName || '');
    setModelsPath(p.modelsPath || '/models');
    setExtraHeaders(headersToText(p.extraHeaders));
    setCredentialHosts(p.credentialHosts || '');
    setFollowRedirects(!!p.followRedirects);
    setAllowInsecureTls(!!p.allowInsecureTls);
    setWirePlugin(p.wirePlugin || '');
    setCredentialPlugin(p.credentialPlugin || '');
    setModelSourcePlugin(p.modelSourcePlugin || '');
    setTimeoutMs(p.timeoutMs || 120000);
    setCapabilityMode(p.capabilityMode || 'permissive');
    // Credentials are never returned by the API; leave the key field blank.
    setApiKey('');
    setAccountLabel('');
    setValidation(null);
    setShowAddProviderModal(true);
  };

  const providerBody = (includeKey = false) => ({
    name: name.trim(),
    base_url: baseUrl.trim(),
    wire_format: wireFormat,
    auth_scheme: authScheme,
    custom_header_name: authScheme === 'custom_header' ? customHeader.trim() || null : null,
    custom_param_name: authScheme === 'query_param' ? customParam.trim() || null : null,
    extra_headers: parseHeaders(extraHeaders),
    timeout_ms: timeoutMs,
    capability_mode: capabilityMode,
    models_path: modelsPath.trim() || null,
    credential_hosts: credentialHosts.trim(),
    follow_redirects: followRedirects,
    allow_insecure_tls: allowInsecureTls,
    wire_plugin: wirePlugin.trim(),
    credential_plugin: credentialPlugin.trim(),
    model_source_plugin: modelSourcePlugin.trim(),
    // Only sent when the admin actually typed a credential.
    ...(includeKey && apiKey.trim()
      ? { api_key: apiKey.trim(), account_label: accountLabel.trim() || null }
      : {}),
  });

  const handleValidateProvider = async () => {
    if (!name.trim() || !baseUrl.trim()) return;
    setValidating(true);
    try {
      const r = await Kinetix.validateProvider(providerBody(false));
      setValidation({ valid: r.valid, problems: r.problems || [], warnings: r.warnings || [] });
    } catch (e) {
      setValidation({ valid: false, problems: [(e as Error).message], warnings: [] });
    } finally {
      setValidating(false);
    }
  };

  const handleCreateProvider = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !baseUrl.trim()) return;

    const prov: Provider = {
      id: editingProviderId || '',
      name: name.trim(),
      baseUrl: baseUrl.trim(),
      wireFormat,
      authScheme,
      customHeaderName: authScheme === 'custom_header' ? customHeader : undefined,
      customParamName: authScheme === 'query_param' ? customParam : undefined,
      status: 'healthy',
      modelsCount: 0,
      accountsCount: 0,
      extraHeaders: parseHeaders(extraHeaders),
      modelsPath: modelsPath.trim() || undefined,
      timeoutMs,
      capabilityMode,
      followRedirects,
      credentialHosts: credentialHosts.trim(),
      allowInsecureTls,
      wirePlugin: wirePlugin.trim(),
      credentialPlugin: credentialPlugin.trim(),
      modelSourcePlugin: modelSourcePlugin.trim(),
      lastPingMs: 0,
    };

    setIsSaving(true);
    try {
      if (editingProviderId) {
        // api_key is omitted unless a new one was typed (rotating the pool key).
        await onUpdateProvider(editingProviderId, {
          ...prov,
          ...(apiKey.trim() ? { apiKey: apiKey.trim() } : {}),
          ...(accountLabel.trim() ? { accountLabel: accountLabel.trim() } : {}),
        });
      } else {
        await onAddProvider({
          ...prov,
          ...(apiKey.trim() ? { apiKey: apiKey.trim() } : {}),
          ...(accountLabel.trim() ? { accountLabel: accountLabel.trim() } : {}),
        });
        setSelectedProviderId(prov.id);
      }
      setShowAddProviderModal(false);
      resetProviderForm();
    } finally {
      setIsSaving(false);
    }
  };

  /** Prefill the model form for editing an existing model. */
  const openEditModel = (m: ModelConfig) => {
    setEditingModelId(m.id);
    setModelUpstreamId(m.upstreamModelId);
    setModelDisplayName(m.displayName);
    setModelContextWindow(m.contextWindow || DEFAULT_CONTEXT_WINDOW);
    setModelMaxOutput(m.maxOutputTokens || DEFAULT_MAX_OUTPUT);
    setModelInputPrice(m.prices.inputPer1M || 0);
    setModelOutputPrice(m.prices.outputPer1M || 0);
    setCapText(m.capabilities.text);
    setCapVision(m.capabilities.vision);
    setCapReasoning(m.capabilities.reasoning);
    setCapTools(m.capabilities.toolCalling);
    setModelValidation(null);
    setShowAddModelModal(true);
  };

  const resetModelForm = () => {
    setEditingModelId(null);
    setModelUpstreamId('');
    setModelDisplayName('');
    setModelContextWindow(DEFAULT_CONTEXT_WINDOW);
    setModelMaxOutput(DEFAULT_MAX_OUTPUT);
    setModelInputPrice(1.0);
    setModelOutputPrice(4.0);
    setCapText(true);
    setCapVision(true);
    setCapReasoning(false);
    setCapTools(true);
    setModelValidation(null);
  };

  const handleCreateCustomModel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!modelUpstreamId.trim()) return;

    const newModel: ModelConfig = {
      id: editingModelId || '',
      providerId: activeProvider.id,
      providerName: activeProvider.name,
      upstreamModelId: modelUpstreamId.trim(),
      displayName: modelDisplayName.trim() || modelUpstreamId.trim(),
      enabled: editingModelId
        ? (models.find((m) => m.id === editingModelId)?.enabled ?? true)
        : true,
      contextWindow: Number(modelContextWindow) || DEFAULT_CONTEXT_WINDOW,
      maxOutputTokens: Number(modelMaxOutput) || DEFAULT_MAX_OUTPUT,
      capabilities: {
        text: capText,
        vision: capVision,
        reasoning: capReasoning,
        toolCalling: capTools,
        audio: false,
      },
      prices: {
        inputPer1M: Number(modelInputPrice) || 0,
        outputPer1M: Number(modelOutputPrice) || 0,
        cachedPer1M: Number(modelInputPrice ? (modelInputPrice * 0.25).toFixed(2) : 0),
        thinkingPer1M: capReasoning ? Number(modelOutputPrice) || 0 : 0,
      },
      parameters: {},
      thinkingMap: {
        scale: capReasoning ? 'medium' : 'off',
        mappedField: capReasoning ? 'thinkingConfig' : '',
      },
    };

    if (editingModelId) {
      onUpdateModel(newModel);
    } else {
      onAddModel(newModel);
    }
    setShowAddModelModal(false);
    resetModelForm();
  };

  const modelBody = () => ({
    upstream_id: modelUpstreamId.trim(),
    display_name: modelDisplayName.trim() || modelUpstreamId.trim(),
    enabled: true,
    context_window: Number(modelContextWindow) || DEFAULT_CONTEXT_WINDOW,
    max_output_tokens: Number(modelMaxOutput) || DEFAULT_MAX_OUTPUT,
    capabilities: { text: capText, vision: capVision, reasoning: capReasoning, tool_calling: capTools, audio: false },
    prices: {
      input_per_1m: Number(modelInputPrice) || null,
      output_per_1m: Number(modelOutputPrice) || null,
    },
  });

  const handleValidateModel = async () => {
    if (!modelUpstreamId.trim()) return;
    setValidatingModel(true);
    try {
      const r = await Kinetix.validateModel(modelBody());
      setModelValidation({ valid: r.valid, problems: r.problems || [], warnings: r.warnings || [] });
    } catch (e) {
      setModelValidation({ valid: false, problems: [(e as Error).message], warnings: [] });
    } finally {
      setValidatingModel(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-heading font-bold text-[var(--ink)] flex items-center gap-2">
            <span>Upstream Providers & Models</span>
            <SketchBadge variant="yellow" rotation="-1deg">
              No Vendor Presets (FR-10)
            </SketchBadge>
          </h2>
          <p className="text-base font-body text-[var(--ink)]/80">
            Configure upstream LLM APIs, fetch model lists, define parameter clamping, and map thinking controls.
          </p>
        </div>

        <SketchButton
          variant="primary"
          size="md"
          onClick={() => {
            resetProviderForm();
            setShowAddProviderModal(true);
          }}
          className="gap-2 font-heading font-bold"
        >
          <Plus className="w-5 h-5" />
          Add Upstream Provider
        </SketchButton>
      </div>

      {/* Main layout */}
      {providers.length === 0 ? (
        <WobblyCard decoration="tack" className="p-10 text-center bg-[var(--surface)]">
          <Server className="w-12 h-12 text-[var(--pen-blue)] mx-auto mb-3 opacity-60" />
          <h3 className="text-2xl font-heading font-bold text-[var(--ink)]">No Upstream Providers Configured</h3>
          <p className="text-base font-body text-[var(--ink)]/80 max-w-lg mx-auto mt-2 mb-6">
            Register your upstream LLM providers (e.g. Gemini, OpenAI, Anthropic, DeepSeek, or local Ollama). Kinetix proxies client calls and maps protocols automatically.
          </p>
          <SketchButton
            variant="primary"
            size="md"
            onClick={() => {
              resetProviderForm();
              setShowAddProviderModal(true);
            }}
            className="gap-2 font-heading font-bold"
          >
            <Plus className="w-5 h-5" />
            Add First Upstream Provider
          </SketchButton>
        </WobblyCard>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Providers Selector */}
          <div className="space-y-4">
            <h3 className="text-xl font-heading font-bold text-[var(--ink)] flex items-center gap-2">
              <Server className="w-5 h-5 text-[var(--pen-blue)]" />
              Configured Upstreams ({providers.length})
            </h3>

            {providers.map((prov, idx) => {
              const isSelected = prov.id === activeProvider?.id;
              const tilt = idx % 2 === 0 ? '-rotate-0.5' : 'rotate-0.5';
              const ping = pingStatus[prov.id];

              return (
                <div
                  key={prov.id}
                  onClick={() => {
                    setSelectedProviderId(prov.id);
                    setDiscoveryResults(null);
                  }}
                  className={`p-4 border-2 border-[var(--ink)] cursor-pointer transition-all ${tilt} ${
                    isSelected
                      ? 'bg-[var(--postit)] sketch-shadow -translate-y-1 font-bold'
                      : 'bg-[var(--surface)] hover:bg-[var(--erased-soft)] sketch-shadow-sm'
                  }`}
                  style={{ borderRadius: DESIGN_TOKENS.radii.wobblyMd }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="font-mono text-xs px-2 py-0.5 bg-[var(--surface)] border border-[var(--ink)] rounded uppercase">
                        {prov.wireFormat} wire
                      </span>
                      <h4 className="font-heading text-lg mt-1 text-[var(--ink)]">{prov.name}</h4>
                      <p className="text-xs font-mono text-[var(--ink)]/70 truncate max-w-[200px]">
                        {prov.baseUrl}
                      </p>
                    </div>

                    <div className="flex flex-col items-end gap-1">
                      <SketchBadge variant={prov.status === 'healthy' ? 'green' : prov.status === 'degraded' ? 'yellow' : 'red'}>
                        {prov.status}
                      </SketchBadge>
                      {ping && (
                        <span className={`text-xs font-mono ${ping.ok ? 'text-[var(--pen-green)]' : 'text-[var(--marker-red)]'}`}>
                          {ping.ok ? `${ping.pingMs}ms` : 'error'}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="mt-3 pt-2 border-t border-[var(--ink)]/20 flex items-center justify-between text-xs font-mono">
                    <span>Auth: <strong>{prov.authScheme}</strong></span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleTestPing(prov.id);
                      }}
                      className="hover:underline text-[var(--pen-blue)] cursor-pointer"
                    >
                      {pingStatus[prov.id] ? (pingStatus[prov.id].ok ? '⚡ OK' : '⚡ Failed') : '⚡ Test Ping'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Active Provider & Models Editor */}
          {activeProvider && (
            <div className="lg:col-span-2 space-y-6">
              <WobblyCard decoration="tape" className="p-6">
                {/* Provider Info Header */}
                <div className="flex flex-wrap items-start justify-between gap-4 pb-4 border-b-2 border-dashed border-[var(--ink)]/30 mb-4">
                  <div>
                    <h3 className="text-2xl font-heading font-bold text-[var(--ink)] flex items-center gap-2">
                      <Globe className="w-6 h-6 text-[var(--pen-blue)]" />
                      {activeProvider.name}
                    </h3>
                    <code className="text-sm font-mono text-[var(--ink)]/80 bg-[var(--erased)] px-2 py-0.5 rounded border border-[var(--ink)]/30 inline-block mt-1">
                      Base URL: {activeProvider.baseUrl}
                    </code>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <SketchButton
                      variant="secondary"
                      size="sm"
                      disabled={isDiscovering}
                      onClick={handleFetchModelsDiscovery}
                      className="gap-1.5 font-heading"
                    >
                      <RefreshCw className={`w-4 h-4 ${isDiscovering ? 'animate-spin' : ''}`} />
                      {isDiscovering ? 'Querying Upstream...' : 'Fetch Models (Discovery)'}
                    </SketchButton>
                    <SketchButton
                      variant="secondary"
                      size="sm"
                      onClick={() => openEditProvider(activeProvider)}
                      className="gap-1.5 font-heading"
                    >
                      <Sliders className="w-4 h-4" />
                      Edit
                    </SketchButton>
                    <SketchButton
                      variant="primary"
                      size="sm"
                      onClick={() => setShowAddModelModal(true)}
                      className="gap-1 font-heading font-bold"
                    >
                      <Plus className="w-4 h-4" />
                      Add Model
                    </SketchButton>

                    {confirmDeleteProviderId === activeProvider.id ? (
                      <div className="flex items-center gap-1 bg-[var(--tint-red)] px-2.5 py-1 border border-[var(--marker-red)] rounded text-xs font-heading">
                        <span className="text-[var(--danger-text)] font-bold">Delete {activeProvider.name}?</span>
                        <button
                          onClick={() => {
                            onDeleteProvider(activeProvider.id);
                            setConfirmDeleteProviderId(null);
                          }}
                          className="px-2 py-0.5 bg-[var(--marker-red)] text-[var(--surface)] rounded font-bold hover:brightness-90 cursor-pointer"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setConfirmDeleteProviderId(null)}
                          className="px-2 py-0.5 bg-[var(--surface)] border border-[var(--ink)] rounded hover:bg-[var(--erased)] cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setConfirmDeleteProviderId(activeProvider.id)}
                        className="px-2.5 py-1 text-xs font-heading font-bold text-[var(--marker-red)] hover:bg-[var(--tint-red)] border border-[var(--marker-red)]/50 hover:border-[var(--marker-red)] rounded flex items-center gap-1 cursor-pointer transition-colors"
                        title="Delete this upstream provider"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Delete Provider</span>
                      </button>
                    )}
                  </div>
                </div>

              {/* Model Discovery Results (if any) */}
              {discoveryResults && (
                <div className="p-4 bg-[var(--postit)] border-2 border-[var(--ink)] sketch-shadow-sm mb-6 rounded-lg">
                  <h4 className="font-heading font-bold text-lg text-[var(--ink)] mb-1">
                    🔍 Discovered Upstream Models (Live Probe)
                  </h4>
                  <p className="text-sm font-body text-[var(--ink)]/80 mb-3">
                    The endpoint returned the following model IDs. Select which models to import into Kinetix:
                  </p>
                  {discoveryResults.length > 0 && (
                    <div className="mb-3">
                      <input
                        type="text"
                        value={discoverySearch}
                        onChange={(e) => setDiscoverySearch(e.target.value)}
                        placeholder={`Search ${discoveryResults.length} models… (fuzzy)`}
                        className="w-full md:w-96 px-3 py-1.5 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-sm rounded outline-none focus:border-[var(--pen-blue)]"
                      />
                    </div>
                  )}
                  <div className="flex flex-wrap gap-2">
                    {discoveryResults.length === 0 && (
                      <span className="text-sm font-mono text-[var(--danger-text)]">
                        No models returned (check the credential or the error above).
                      </span>
                    )}
                    {discoveryResults.length > 0 &&
                      filteredDiscovery.map((m) => (
                      <div
                        key={m.id}
                        className="bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-1.5 text-xs font-mono sketch-shadow-sm flex items-center gap-2 rounded"
                      >
                        <span className="font-bold">{m.id}</span>
                        {m.context_window ? (
                          <span className="text-[var(--ink)]/50">{m.context_window.toLocaleString()} ctx</span>
                        ) : null}
                        {m.already_imported ? (
                          <span className="text-[var(--pen-green)] font-bold">✓ imported</span>
                        ) : (
                          <button
                            onClick={() => handleImportDiscoveredModel(m)}
                            className="bg-[var(--pen-green)] text-[var(--surface)] px-2 py-0.5 rounded hover:bg-[var(--success-text)] cursor-pointer"
                          >
                            + Import
                          </button>
                        )}
                      </div>
                    ))}
                    {discoveryResults.length > 0 && filteredDiscovery.length === 0 && (
                      <span className="text-sm font-mono text-[var(--ink)]/60">
                        No models match “{discoverySearch}”.
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Models List for this Provider */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-xl font-heading font-bold text-[var(--ink)] flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-[var(--marker-red)]" />
                    Configured Models ({providerModels.length})
                  </h4>
                  {providerModels.length > 0 && (
                    <button
                      onClick={() => setShowAddModelModal(true)}
                      className="text-xs font-heading font-bold text-[var(--pen-blue)] hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      Configure Another Model
                    </button>
                  )}
                </div>

                {providerModels.length === 0 ? (
                  <div className="p-8 text-center bg-[var(--surface)] border-2 border-dashed border-[var(--ink)]/30 rounded-lg">
                    <Cpu className="w-10 h-10 text-[var(--ink)]/40 mx-auto mb-2" />
                    <p className="font-heading font-bold text-lg text-[var(--ink)]">No Models Configured</p>
                    <p className="text-sm font-body text-[var(--ink)]/70 max-w-md mx-auto mt-1 mb-4">
                      Probe upstream models via live discovery or manually register custom upstream model IDs for this provider.
                    </p>
                    <div className="flex items-center justify-center gap-3">
                      <SketchButton
                        variant="secondary"
                        size="sm"
                        onClick={handleFetchModelsDiscovery}
                        disabled={isDiscovering}
                      >
                        Fetch Models (Discovery)
                      </SketchButton>
                      <SketchButton
                        variant="primary"
                        size="sm"
                        onClick={() => setShowAddModelModal(true)}
                      >
                        + Add Custom Model
                      </SketchButton>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {providerModels.map((m) => (
                      <div
                        key={m.id}
                        className="p-4 bg-[var(--surface)] border-2 border-[var(--ink)] sketch-shadow-sm rounded-lg"
                      >
                        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b border-[var(--ink)]/20 pb-2 mb-3">
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-heading font-bold text-lg text-[var(--ink)]">
                                {m.displayName}
                              </span>
                              <span className="text-xs font-mono bg-[var(--erased)] px-1.5 py-0.5 rounded border border-[var(--ink)]/40">
                                id: {m.upstreamModelId}
                              </span>
                            </div>
                            <span className="text-xs font-mono text-[var(--ink)]/70">
                              Context: {(m.contextWindow || DEFAULT_CONTEXT_WINDOW).toLocaleString()} tokens • Max Output: {m.maxOutputTokens || DEFAULT_MAX_OUTPUT}
                            </span>
                          </div>

                          {/* Capabilities badges & Delete button */}
                          <div className="flex flex-wrap items-center gap-2">
                            <div className="flex flex-wrap items-center gap-1">
                              {m.capabilities.text && <SketchBadge variant="default">Text</SketchBadge>}
                              {m.capabilities.vision && <SketchBadge variant="blue">Vision</SketchBadge>}
                              {m.capabilities.reasoning && <SketchBadge variant="yellow">Reasoning</SketchBadge>}
                              {m.capabilities.toolCalling && <SketchBadge variant="green">Tools</SketchBadge>}
                            </div>

                            {confirmDeleteModelId === m.id ? (
                              <div className="flex items-center gap-1 bg-[var(--tint-red)] px-2 py-1 border border-[var(--marker-red)] rounded text-xs font-heading">
                                <span className="text-[var(--danger-text)] font-bold">Remove model?</span>
                                <button
                                  onClick={() => {
                                    onDeleteModel(m.id);
                                    setConfirmDeleteModelId(null);
                                  }}
                                  className="px-2 py-0.5 bg-[var(--marker-red)] text-[var(--surface)] rounded font-bold hover:brightness-90 cursor-pointer"
                                >
                                  Delete
                                </button>
                                <button
                                  onClick={() => setConfirmDeleteModelId(null)}
                                  className="px-2 py-0.5 bg-[var(--surface)] border border-[var(--ink)] rounded hover:bg-[var(--erased)] cursor-pointer"
                                >
                                  Cancel
                                </button>
                              </div>
                            ) : (
                              <div className="flex items-center gap-1">
                                <button
                                  onClick={() => openEditModel(m)}
                                  className="px-2 py-1 text-xs font-heading font-bold text-[var(--pen-blue)] hover:bg-[var(--tint-blue)] border border-[var(--pen-blue)]/40 hover:border-[var(--pen-blue)] rounded flex items-center gap-1 cursor-pointer transition-colors"
                                  title="Edit model configuration"
                                >
                                  <Pencil className="w-3.5 h-3.5" />
                                  <span>Edit</span>
                                </button>
                                <button
                                  onClick={() => setConfirmDeleteModelId(m.id)}
                                  className="px-2 py-1 text-xs font-heading font-bold text-[var(--marker-red)] hover:bg-[var(--tint-red)] border border-[var(--marker-red)]/40 hover:border-[var(--marker-red)] rounded flex items-center gap-1 cursor-pointer transition-colors"
                                  title="Remove model from provider"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                  <span>Remove</span>
                                </button>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Prices & Parameter policies */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                          <div className="bg-[var(--paper)] p-2 border border-[var(--ink)] rounded">
                            <strong className="font-heading text-sm text-[var(--ink)] block mb-1">
                              💵 Token Pricing (Admin Defined)
                            </strong>
                            <div>Input: ${m.prices.inputPer1M} / 1M</div>
                            <div>Output: ${m.prices.outputPer1M} / 1M</div>
                            <div>Cached: ${m.prices.cachedPer1M} / 1M</div>
                            {m.capabilities.reasoning && (
                              <div>Thinking: ${m.prices.thinkingPer1M} / 1M</div>
                            )}
                          </div>

                          <div className="bg-[var(--paper)] p-2 border border-[var(--ink)] rounded">
                            <strong className="font-heading text-sm text-[var(--ink)] block mb-1">
                              ⚙️ Parameter & Thinking Controls
                            </strong>
                            <div>Temperature Policy: <strong>Clamp (0.0 - 2.0)</strong></div>
                            <div>
                              Thinking Scale:{' '}
                              <strong className="text-[var(--pen-blue)]">{m.thinkingMap.scale}</strong>
                            </div>
                            <div className="truncate">
                              Mapped Field: <code>{m.thinkingMap.mappedField}</code>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </WobblyCard>
          </div>
        )}
      </div>
    )}

      {/* Add Provider Modal */}
      {showAddProviderModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-xs">
          <div className="w-full max-w-lg">
            <WobblyCard decoration="tape" className="bg-[var(--paper)] p-6 relative">
              <button
                onClick={() => setShowAddProviderModal(false)}
                className="absolute top-4 right-4 text-[var(--ink)] font-bold text-xl hover:text-[var(--marker-red)] cursor-pointer"
              >
                ✕
              </button>

              <h3 className="text-2xl font-heading font-bold text-[var(--ink)] mb-4 flex items-center gap-2">
                <Server className="w-6 h-6 text-[var(--pen-blue)]" />
                {editingProviderId ? 'Edit Upstream Provider' : 'Add Upstream Provider (No Presets)'}
              </h3>

              <form onSubmit={handleCreateProvider} className="space-y-4 font-body">
                <div>
                  <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                    Provider Name
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Google Gemini, Mistral, Local vLLM"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base sketch-shadow-sm focus:outline-none"
                    style={{ borderRadius: DESIGN_TOKENS.radii.wobblyMd }}
                  />
                </div>

                <div>
                  <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                    Endpoint Base URL
                  </label>
                  <input
                    type="url"
                    required
                    placeholder="https://api.openai.com/v1 or custom host"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    style={{ borderRadius: DESIGN_TOKENS.radii.wobbly }}
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Wire Format
                    </label>
                    <select
                      value={wireFormat}
                      onChange={(e) => setWireFormat(e.target.value as any)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base sketch-shadow-sm focus:outline-none font-mono"
                      style={{ borderRadius: DESIGN_TOKENS.radii.wobblyMd }}
                    >
                      <option value="gemini">Gemini API</option>
                      <option value="openai">OpenAI Compatible</option>
                      <option value="anthropic">Anthropic Messages</option>
                      <option value="plugin">Plugin adapter</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Auth Scheme
                    </label>
                    <select
                      value={authScheme}
                      onChange={(e) => setAuthScheme(e.target.value as any)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base sketch-shadow-sm focus:outline-none font-mono"
                      style={{ borderRadius: '255px 15px 225px 15px / 15px 225px 15px 255px' }}
                    >
                      <option value="bearer">Bearer Header (Authorization)</option>
                      <option value="custom_header">Custom Header (e.g. x-api-key)</option>
                      <option value="query_param">Query Param (?key=...)</option>
                    </select>
                  </div>
                </div>

                {authScheme === 'custom_header' && (
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Custom Header Name
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. x-api-key"
                      value={customHeader}
                      onChange={(e) => setCustomHeader(e.target.value)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>
                )}

                {authScheme === 'query_param' && (
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Custom Query Parameter Name
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. key"
                      value={customParam}
                      onChange={(e) => setCustomParam(e.target.value)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Models Path
                    </label>
                    <input
                      type="text"
                      placeholder="/models"
                      value={modelsPath}
                      onChange={(e) => setModelsPath(e.target.value)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Extra Headers
                    </label>
                    <textarea
                      rows={2}
                      placeholder={'anthropic-version: 2023-06-01'}
                      value={extraHeaders}
                      onChange={(e) => setExtraHeaders(e.target.value)}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-sm font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>
                </div>

                {/* Credential — needed for authenticated model discovery, and to
                    create the provider's first account (FR-10.11). */}
                <div
                  className="p-3 bg-[var(--postit)]/60 border-2 border-dashed border-[var(--ink)]/40"
                  style={{ borderRadius: DESIGN_TOKENS.radii.wobbly }}
                >
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                        API Key {editingProviderId ? '(leave blank to keep)' : '(optional)'}
                      </label>
                      <input
                        type="password"
                        autoComplete="off"
                        placeholder={editingProviderId ? '•••••• (unchanged)' : 'sk-... or provider key'}
                        value={apiKey}
                        onChange={(e) => setApiKey(e.target.value)}
                        className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                        Account Label
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. Primary key"
                        value={accountLabel}
                        onChange={(e) => setAccountLabel(e.target.value)}
                        className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                      />
                    </div>
                  </div>
                  <p className="text-xs font-body text-[var(--ink)]/70 mt-2">
                    Stored encrypted at rest. Required to fetch an authenticated upstream model list
                    and to create the first account for this provider.
                  </p>
                </div>

                <details className="text-sm font-body">
                  <summary className="cursor-pointer font-heading font-bold text-[var(--pen-blue)]">
                    Advanced (security & timeout)
                  </summary>
                  <div className="grid grid-cols-2 gap-3 mt-3">                    <div>
                      <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                        Timeout (ms)
                      </label>
                      <input
                        type="number"
                        min={1000}
                        value={timeoutMs}
                        onChange={(e) => setTimeoutMs(Number(e.target.value) || 120000)}
                        className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                        Capability Mode
                      </label>
                      <select
                        value={capabilityMode}
                        onChange={(e) => setCapabilityMode(e.target.value as any)}
                        className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                      >
                        <option value="permissive">Permissive (never reject on caps)</option>
                        <option value="strict">Strict (reject unmet caps)</option>
                      </select>
                    </div>
                    <div className="col-span-2 p-3 border-2 border-dashed border-[var(--ink)]/30 bg-[var(--surface)]/70">
                      <div className="font-heading font-bold text-sm mb-2">Plugin bindings (optional)</div>
                      <p className="text-xs font-body text-[var(--ink)]/65 mb-3">
                        Bind this provider to capabilities from an enabled plugin. Use the explicit{' '}
                        <code>plugin:&lt;id&gt;/&lt;capability&gt;</code> reference shown on the Plugins page.
                      </p>
                      <div className="space-y-2">
                        <label className="block">
                          <span className="block text-xs font-heading font-bold mb-1">Wire adapter</span>
                          <input
                            type="text"
                            placeholder="plugin:dev.example.foo/foo-wire"
                            value={wirePlugin}
                            onChange={(e) => setWirePlugin(e.target.value)}
                            className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-sm font-mono sketch-shadow-sm focus:outline-none"
                          />
                        </label>
                        <label className="block">
                          <span className="block text-xs font-heading font-bold mb-1">Credential strategy</span>
                          <input
                            type="text"
                            placeholder="plugin:dev.example.foo/foo-oauth"
                            value={credentialPlugin}
                            onChange={(e) => setCredentialPlugin(e.target.value)}
                            className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-sm font-mono sketch-shadow-sm focus:outline-none"
                          />
                        </label>
                        <label className="block">
                          <span className="block text-xs font-heading font-bold mb-1">Model source</span>
                          <input
                            type="text"
                            placeholder="plugin:dev.example.foo/foo-models"
                            value={modelSourcePlugin}
                            onChange={(e) => setModelSourcePlugin(e.target.value)}
                            className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-sm font-mono sketch-shadow-sm focus:outline-none"
                          />
                        </label>
                      </div>
                    </div>
                    <div className="col-span-2">
                      <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                        Credential Host Binding (comma-separated, optional)
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. api.example.com, uploads.example.com"
                        value={credentialHosts}
                        onChange={(e) => setCredentialHosts(e.target.value)}
                        className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                      />
                    </div>
                    <label className="flex items-center gap-2 font-body text-sm">
                      <input
                        type="checkbox"
                        checked={followRedirects}
                        onChange={(e) => setFollowRedirects(e.target.checked)}
                      />
                      Follow redirects (default off)
                    </label>
                    <label className="flex items-center gap-2 font-body text-sm">
                      <input
                        type="checkbox"
                        checked={allowInsecureTls}
                        onChange={(e) => setAllowInsecureTls(e.target.checked)}
                      />
                      Allow plain-HTTP (dev only)
                    </label>
                  </div>
                </details>

                {validation && (
                  <div
                    className="p-3 text-sm font-mono"
                    style={{
                      borderRadius: DESIGN_TOKENS.radii.wobbly,
                      background: validation.valid ? 'var(--tint-green)' : 'var(--tint-red)',
                      border: `2px solid ${validation.valid ? 'var(--pen-green)' : 'var(--marker-red)'}`,
                    }}
                  >
                    <div className="font-bold mb-1">
                      {validation.valid ? 'Validate: passed' : 'Validate: problems found'}
                    </div>
                    {validation.problems.map((p, i) => (
                      <div key={i} style={{ color: 'var(--danger-text)' }}>
                        • {p}
                      </div>
                    ))}
                    {validation.warnings.map((w, i) => (
                      <div key={i} style={{ color: 'var(--marker-orange)' }}>
                        ⚠ {w}
                      </div>
                    ))}
                  </div>
                )}

                <div className="pt-2 flex justify-end gap-3">
                  <SketchButton
                    type="button"
                    variant="ghost"
                    onClick={() => setShowAddProviderModal(false)}
                  >
                    Cancel
                  </SketchButton>
                  <SketchButton
                    type="button"
                    variant="secondary"
                    onClick={handleValidateProvider}
                    disabled={validating || !name.trim() || !baseUrl.trim()}
                  >
                    {validating ? 'Validating…' : 'Validate (Dry Run)'}
                  </SketchButton>
                  <SketchButton type="submit" variant="danger" className="font-bold" disabled={isSaving}>
                    {isSaving ? 'Saving…' : editingProviderId ? 'Save Changes' : 'Save Provider'}
                  </SketchButton>
                </div>
              </form>
            </WobblyCard>
          </div>
        </div>
      )}

      {/* Add Model Modal */}
      {showAddModelModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-xs">
          <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <WobblyCard decoration="tack" className="bg-[var(--paper)] p-6 relative">
              <button
                onClick={() => setShowAddModelModal(false)}
                className="absolute top-4 right-4 text-[var(--ink)] font-bold text-xl hover:text-[var(--marker-red)] cursor-pointer"
              >
                ✕
              </button>

              <h3 className="text-2xl font-heading font-bold text-[var(--ink)] mb-1 flex items-center gap-2">
                <Cpu className="w-6 h-6 text-[var(--marker-red)]" />
                {editingModelId ? `Edit Model for ${activeProvider.name}` : `Configure Model for ${activeProvider.name}`}
              </h3>
              <p className="text-sm font-body text-[var(--ink)]/80 mb-4">
                Define the model identifier, token capabilities, and per-million token pricing.
              </p>

              <form onSubmit={handleCreateCustomModel} className="space-y-4">
                <div>
                  <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                    Upstream Model ID (Wire Name)
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. gemini-2.5-flash, claude-3-7-sonnet, gpt-4o"
                    value={modelUpstreamId}
                    onChange={(e) => setModelUpstreamId(e.target.value)}
                    className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    style={{ borderRadius: DESIGN_TOKENS.radii.wobblyMd }}
                  />
                </div>

                <div>
                  <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                    Display Name
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Gemini 2.5 Flash (Production)"
                    value={modelDisplayName}
                    onChange={(e) => setModelDisplayName(e.target.value)}
                    className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base sketch-shadow-sm focus:outline-none"
                    style={{ borderRadius: DESIGN_TOKENS.radii.wobbly }}
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Context Window
                    </label>
                    <input
                      type="number"
                      min={0}
                      step={1000}
                      placeholder={`${DEFAULT_CONTEXT_WINDOW} (default)`}
                      value={modelContextWindow}
                      onChange={(e) => setModelContextWindow(Number(e.target.value))}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-1">
                      Max Output
                    </label>
                    <input
                      type="number"
                      min={0}
                      placeholder={`${DEFAULT_MAX_OUTPUT} (default)`}
                      value={modelMaxOutput}
                      onChange={(e) => setModelMaxOutput(Number(e.target.value))}
                      className="w-full bg-[var(--surface)] border-2 border-[var(--ink)] px-3 py-2 text-base font-mono sketch-shadow-sm focus:outline-none"
                    />
                  </div>
                </div>

                <p className="text-xs font-body text-[var(--ink)]/60">
                  If a value is unknown, leave it as 0 (or blank) to apply the defaults:{' '}
                  {DEFAULT_CONTEXT_WINDOW.toLocaleString()} context window · {DEFAULT_MAX_OUTPUT.toLocaleString()} max output.
                </p>

                {/* Token Pricing */}
                <div className="grid grid-cols-2 gap-3 bg-[var(--erased-soft)] p-3 border border-[var(--ink)] rounded">
                  <div>
                    <label className="block text-xs font-heading font-bold text-[var(--ink)] mb-1">
                      Input Price ($ / 1M)
                    </label>
                    <input
                      type="number"
                      step={0.01}
                      min={0}
                      value={modelInputPrice}
                      onChange={(e) => setModelInputPrice(Number(e.target.value))}
                      className="w-full bg-[var(--surface)] border border-[var(--ink)] px-2 py-1 text-sm font-mono focus:outline-none rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-heading font-bold text-[var(--ink)] mb-1">
                      Output Price ($ / 1M)
                    </label>
                    <input
                      type="number"
                      step={0.01}
                      min={0}
                      value={modelOutputPrice}
                      onChange={(e) => setModelOutputPrice(Number(e.target.value))}
                      className="w-full bg-[var(--surface)] border border-[var(--ink)] px-2 py-1 text-sm font-mono focus:outline-none rounded"
                    />
                  </div>
                </div>

                {/* Capabilities */}
                <div>
                  <label className="block text-sm font-heading font-bold text-[var(--ink)] mb-2">
                    Model Capabilities
                  </label>
                  <div className="grid grid-cols-2 gap-2 text-sm font-body">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={capText}
                        onChange={(e) => setCapText(e.target.checked)}
                        className="w-4 h-4 accent-[var(--marker-red)]"
                      />
                      <span>Text Generation</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={capVision}
                        onChange={(e) => setCapVision(e.target.checked)}
                        className="w-4 h-4 accent-[var(--marker-red)]"
                      />
                      <span>Vision / Multimodal</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={capReasoning}
                        onChange={(e) => setCapReasoning(e.target.checked)}
                        className="w-4 h-4 accent-[var(--marker-red)]"
                      />
                      <span>Reasoning / Thinking</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={capTools}
                        onChange={(e) => setCapTools(e.target.checked)}
                        className="w-4 h-4 accent-[var(--marker-red)]"
                      />
                      <span>Tool Calling / JSON</span>
                    </label>
                  </div>
                </div>

                <div className="pt-2 flex justify-end gap-3">
                  <SketchButton
                    type="button"
                    variant="ghost"
                    onClick={() => setShowAddModelModal(false)}
                  >
                    Cancel
                  </SketchButton>
                  <SketchButton
                    type="button"
                    variant="secondary"
                    onClick={handleValidateModel}
                    disabled={validatingModel || !modelUpstreamId.trim()}
                  >
                    {validatingModel ? 'Validating…' : 'Validate (Dry Run)'}
                  </SketchButton>
                  <SketchButton type="submit" variant="primary" className="font-bold">
                    {editingModelId ? 'Save Changes' : 'Save Model Configuration'}
                  </SketchButton>
                </div>
                {modelValidation && (
                  <div
                    className="mt-3 p-3 text-sm font-mono"
                    style={{
                      borderRadius: DESIGN_TOKENS.radii.wobbly,
                      background: modelValidation.valid ? 'var(--tint-green)' : 'var(--tint-red)',
                      border: `2px solid ${modelValidation.valid ? 'var(--pen-green)' : 'var(--marker-red)'}`,
                    }}
                  >
                    <div className="font-bold mb-1">
                      {modelValidation.valid ? 'Validate: passed' : 'Validate: problems found'}
                    </div>
                    {modelValidation.problems.map((p, i) => (
                      <div key={i} style={{ color: 'var(--danger-text)' }}>• {p}</div>
                    ))}
                    {modelValidation.warnings.map((w, i) => (
                      <div key={i} style={{ color: 'var(--marker-orange)' }}>⚠ {w}</div>
                    ))}
                  </div>
                )}
              </form>
            </WobblyCard>
          </div>
        </div>
      )}
    </div>
  );
};
