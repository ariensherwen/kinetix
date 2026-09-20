import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  KeyRound,
  LogIn,
  Network,
  PackagePlus,
  Power,
  PowerOff,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import {
  DiscoveredModel,
  Kinetix,
  PluginCatalogEntry,
  PluginDetail,
  PluginPermissionResponse,
  PluginRollbackPreview,
  PluginSettingState,
  PluginSummary,
} from '../../lib/resources';
import { Provider } from '../../types';
import { SketchBadge, SketchButton, WobblyCard } from '../HandDrawnElements';

function fileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('Failed to read plugin package.'));
    reader.onload = () => {
      const value = String(reader.result ?? '');
      const comma = value.indexOf(',');
      if (comma < 0) {
        reject(new Error('Failed to encode plugin package.'));
        return;
      }
      resolve(value.slice(comma + 1));
    };
    reader.readAsDataURL(file);
  });
}

function requestedGrantPairs(plugin: PluginSummary): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (plugin.permissions.network_hosts.length > 0) {
    out.push(['network_hosts', JSON.stringify(plugin.permissions.network_hosts)]);
  }
  if (plugin.permissions.credential_scopes.length > 0) {
    out.push(['credential_scopes', JSON.stringify(plugin.permissions.credential_scopes)]);
  }
  if (plugin.permissions.credential_read) {
    out.push(['credential_read', 'true']);
  }
  return out;
}

function isFullyApproved(plugin: PluginSummary, permissions: PluginPermissionResponse | null): boolean {
  if (!permissions) return requestedGrantPairs(plugin).length === 0;
  const approved = new Set(
    permissions.approved.map((grant) => `${grant.permission}\0${grant.value_json}`),
  );
  return requestedGrantPairs(plugin).every(
    ([permission, value]) => approved.has(`${permission}\0${value}`),
  );
}

function prettyCapability(capability: string): string {
  return capability
    .replaceAll('_', ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export const PluginsView: React.FC = () => {
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [catalog, setCatalog] = useState<PluginCatalogEntry[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<PluginDetail | null>(null);
  const [permissions, setPermissions] = useState<PluginPermissionResponse | null>(null);
  const [settings, setSettings] = useState<PluginSettingState[]>([]);
  const [settingDrafts, setSettingDrafts] = useState<Record<string, string | boolean>>({});
  const [rollbackPreview, setRollbackPreview] = useState<PluginRollbackPreview | null>(null);
  const [postAuthProviderId, setPostAuthProviderId] = useState<string | null>(null);
  const [postAuthModels, setPostAuthModels] = useState<DiscoveredModel[] | null>(null);
  const [postAuthDiscovering, setPostAuthDiscovering] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [showInstall, setShowInstall] = useState(false);
  const [packageFile, setPackageFile] = useState<File | null>(null);
  const [sha256, setSha256] = useState('');
  const [trustedKeys, setTrustedKeys] = useState('');
  const [allowUntrusted, setAllowUntrusted] = useState(false);

  const loadDetail = useCallback(async (id: string) => {
    const [plugin, grants, settingState] = await Promise.all([
      Kinetix.plugin(id),
      Kinetix.pluginPermissions(id),
      Kinetix.pluginSettings(id),
    ]);
    setDetail(plugin);
    setPermissions(grants);
    setSettings(settingState.settings);

    const drafts: Record<string, string | boolean> = {};
    for (const setting of settingState.settings) {
      if (setting.kind === 'boolean') {
        drafts[setting.key] = setting.value === true;
      } else if (setting.kind === 'secret') {
        drafts[setting.key] = '';
      } else {
        drafts[setting.key] = typeof setting.value === 'string' ? setting.value : '';
      }
    }
    setSettingDrafts(drafts);
  }, []);

  const refresh = useCallback(async (preferredId?: string | null) => {
    setLoading(true);
    try {
      const [rows, providerRows, catalogResponse] = await Promise.all([
        Kinetix.plugins(),
        Kinetix.providers(),
        Kinetix.pluginCatalog(),
      ]);
      setPlugins(rows);
      setProviders(providerRows);
      setCatalog(catalogResponse.plugins);
      const target = preferredId ?? selectedId;
      if (target && rows.some((plugin) => plugin.id === target)) {
        setSelectedId(target);
        await loadDetail(target);
      } else if (rows.length > 0) {
        setSelectedId(rows[0].id);
        await loadDetail(rows[0].id);
      } else {
        setSelectedId(null);
        setDetail(null);
        setPermissions(null);
        setSettings([]);
        setSettingDrafts({});
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [loadDetail, selectedId]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const authResult = params.get('plugin_auth');
    const callbackPluginId = params.get('plugin_id');
    const callbackProviderId = params.get('provider_id');

    if (authResult) {
      const messages: Record<string, string> = {
        success: 'Account connected successfully through the plugin authorization flow.',
        cancelled: 'Account authorization was cancelled.',
        error: 'Account authorization failed during the provider exchange.',
        binding_changed:
          'Account authorization was refused because the provider plugin binding changed during login.',
      };
      const message = messages[authResult] ?? 'Account authorization returned an unknown result.';
      if (authResult === 'success') {
        setNotice(message);
      } else {
        setError(message);
      }
      params.delete('plugin_auth');
      params.delete('plugin_id');
      params.delete('provider_id');
      const query = params.toString();
      window.history.replaceState(
        null,
        '',
        `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`,
      );
    }

    const initialize = async () => {
      await refresh(callbackPluginId);
      if (authResult === 'success' && callbackProviderId) {
        setPostAuthProviderId(callbackProviderId);
        setPostAuthDiscovering(true);
        try {
          const models = await Kinetix.discover(callbackProviderId);
          setPostAuthModels(models.filter((model) => !model.already_imported));
        } catch (err) {
          setError(
            `Account connected, but model discovery failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
          setPostAuthModels([]);
        } finally {
          setPostAuthDiscovering(false);
        }
      }
    };

    void initialize();
    // Initial load only; later refreshes are explicit so selecting an item does
    // not re-run this effect through the selectedId dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectPlugin = async (id: string) => {
    setSelectedId(id);
    setRollbackPreview(null);
    setBusy('detail');
    try {
      await loadDetail(id);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const mutate = async (label: string, fn: () => Promise<unknown>, message: string) => {
    setBusy(label);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(message);
      await refresh(selectedId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const removePlugin = async (id: string) => {
    setBusy('remove');
    setError(null);
    setNotice(null);
    try {
      await Kinetix.removePlugin(id);
      setSelectedId(null);
      setDetail(null);
      setPermissions(null);
      setSettings([]);
      setSettingDrafts({});
      setNotice('Plugin removed.');
      await refresh(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const saveSettings = async () => {
    if (!selectedId) return;
    setBusy('settings');
    setError(null);
    setNotice(null);

    const values: Record<string, unknown> = {};
    for (const setting of settings) {
      const draft = settingDrafts[setting.key];
      if (setting.kind === 'secret') {
        if (typeof draft === 'string' && draft.length > 0) {
          values[setting.key] = draft;
        }
        continue;
      }
      values[setting.key] = draft ?? (setting.kind === 'boolean' ? false : '');
    }

    try {
      const response = await Kinetix.updatePluginSettings(selectedId, values);
      setSettings(response.settings);
      setSettingDrafts((current) => {
        const next = { ...current };
        for (const setting of response.settings) {
          if (setting.kind === 'secret') {
            next[setting.key] = '';
          }
        }
        return next;
      });
      setNotice('Plugin settings saved.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const clearSetting = async (key: string) => {
    if (!selectedId) return;
    setBusy(`setting:${key}`);
    setError(null);
    setNotice(null);
    try {
      const response = await Kinetix.updatePluginSettings(selectedId, { [key]: null });
      setSettings(response.settings);
      setSettingDrafts((current) => ({ ...current, [key]: '' }));
      setNotice(`Cleared plugin setting “${key}”.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const reviewRollback = async (id: string, sha256: string) => {
    setBusy(`preview:${sha256}`);
    setError(null);
    try {
      const preview = await Kinetix.previewPluginRollback(id, sha256);
      setRollbackPreview(preview);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const confirmRollback = async () => {
    if (!selectedId || !rollbackPreview) return;
    const target = rollbackPreview;
    setBusy(`rollback:${target.package_sha256}`);
    setError(null);
    setNotice(null);
    try {
      await Kinetix.rollbackPlugin(selectedId, target.package_sha256);
      setRollbackPreview(null);
      setNotice(
        `Rolled back to v${target.target_version}. Review permissions before enabling.`,
      );
      await refresh(selectedId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const installFromCatalog = async (entry: PluginCatalogEntry) => {
    setBusy(`catalog:${entry.id}`);
    setError(null);
    setNotice(null);
    try {
      const outcome = await Kinetix.installCatalogPlugin(entry.id);
      setNotice(
        `Installed ${outcome.id} v${outcome.version} from the trusted catalog. Review permissions before enabling it.`,
      );
      await refresh(outcome.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const install = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageFile) {
      setError('Choose a .kxp package first.');
      return;
    }
    setBusy('install');
    setError(null);
    setNotice(null);
    try {
      const package_base64 = await fileAsBase64(packageFile);
      const keys = trustedKeys
        .split(/[\n,]/)
        .map((value) => value.trim())
        .filter(Boolean);
      const outcome = await Kinetix.installPlugin({
        package_base64,
        sha256: sha256.trim() || undefined,
        trusted_keys: keys,
        allow_untrusted_signature: allowUntrusted,
      });
      setNotice(
        `Installed ${outcome.id} v${outcome.version}. Review permissions before enabling it.`,
      );
      setShowInstall(false);
      setPackageFile(null);
      setSha256('');
      setTrustedKeys('');
      setAllowUntrusted(false);
      await refresh(outcome.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const importPostAuthModel = async (model: DiscoveredModel) => {
    if (!postAuthProviderId) return;
    setBusy(`post-auth-model:${model.id}`);
    setError(null);
    try {
      await Kinetix.createModel(postAuthProviderId, {
        upstream_id: model.id,
        display_name: model.display_name || model.id,
        enabled: true,
        context_window: model.context_window ?? null,
        max_output_tokens: model.max_output_tokens ?? null,
        capabilities: {},
        prices: {},
        parameters: {},
        thinking_map: {},
        extra_request: {},
      });
      setPostAuthModels((current) => current?.filter((item) => item.id !== model.id) ?? null);
      setNotice(`Imported model ${model.display_name || model.id}.`);
      await refresh(selectedId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const setupAndConnect = async (
    pluginId: string,
    integrationId: string,
    flowName: string,
  ) => {
    setBusy(`setup:${integrationId}`);
    setError(null);
    setNotice(null);
    try {
      const provider = await Kinetix.setupPluginIntegrationProvider(pluginId, integrationId);
      const started = await Kinetix.startPluginAuth(pluginId, flowName, provider.id);
      window.location.assign(started.authorize_url);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(null);
    }
  };

  const connectAccount = async (
    pluginId: string,
    flowName: string,
    providerId: string,
  ) => {
    setBusy(`auth:${flowName}:${providerId}`);
    setError(null);
    setNotice(null);
    try {
      const started = await Kinetix.startPluginAuth(pluginId, flowName, providerId);
      window.location.assign(started.authorize_url);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(null);
    }
  };

  const selected = useMemo(
    () => plugins.find((plugin) => plugin.id === selectedId) ?? detail,
    [plugins, selectedId, detail],
  );
  const fullyApproved = selected ? isFullyApproved(selected, permissions) : false;
  const requested = selected ? requestedGrantPairs(selected) : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-start gap-4">
        <div className="flex-1">
          <h2 className="text-3xl font-heading font-bold text-[var(--ink)] flex items-center gap-2 flex-wrap">
            <Box className="w-7 h-7 text-[var(--pen-blue)]" />
            <span>Plugins &amp; Integrations</span>
            <SketchBadge variant="blue" rotation="1deg">WASM</SketchBadge>
          </h2>
          <p className="text-base font-body text-[var(--ink)]/80 max-w-3xl">
            Install sandboxed <span className="font-mono">.kxp</span> packages, review their requested
            authority, validate them, and control their runtime lifecycle from the dashboard.
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <SketchButton
            variant="secondary"
            onClick={() => void refresh(selectedId)}
            disabled={loading || busy !== null}
            className="gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </SketchButton>
          <SketchButton
            variant="primary"
            onClick={() => setShowInstall((value) => !value)}
            className="gap-2"
          >
            <PackagePlus className="w-4 h-4" />
            Install .kxp
          </SketchButton>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-[var(--tint-red)] border-2 border-[var(--marker-red)] text-sm font-mono text-[var(--danger-text)] flex gap-2 items-start">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {notice && (
        <div className="p-3 bg-[var(--tint-green)] border-2 border-[var(--pen-green)] text-sm font-mono text-[var(--success-text)] flex gap-2 items-start">
          <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{notice}</span>
        </div>
      )}

      {(postAuthDiscovering || postAuthModels !== null) && (
        <WobblyCard decoration="tape" className="p-5">
          <div className="flex flex-col md:flex-row md:items-start gap-4">
            <div className="flex-1">
              <h3 className="text-xl font-heading font-bold">Finish integration setup</h3>
              <p className="text-sm font-body text-[var(--ink)]/75">
                The account is connected. Kinetix is using the provider&apos;s authenticated
                discovery path; choose which newly advertised models to enable.
              </p>
            </div>
            {postAuthDiscovering ? (
              <SketchBadge variant="blue">Discovering…</SketchBadge>
            ) : (
              <SketchButton
                variant="secondary"
                disabled={busy !== null}
                onClick={() => {
                  setPostAuthModels(null);
                  setPostAuthProviderId(null);
                }}
              >
                Done
              </SketchButton>
            )}
          </div>

          {postAuthDiscovering ? (
            <div className="mt-4 text-sm font-mono text-[var(--ink)]/60">
              Fetching the live model catalog…
            </div>
          ) : postAuthModels && postAuthModels.length > 0 ? (
            <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3">
              {postAuthModels.map((model) => (
                <div
                  key={model.id}
                  className="p-3 border-2 border-[var(--ink)]/25 bg-[var(--surface)] flex items-start justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="font-heading font-bold break-words">
                      {model.display_name || model.id}
                    </div>
                    <code className="text-xs break-all text-[var(--ink)]/60">{model.id}</code>
                    <div className="mt-1 text-xs font-mono text-[var(--ink)]/55">
                      {model.context_window
                        ? `${model.context_window.toLocaleString()} ctx`
                        : 'context unknown'}
                      {' · '}
                      {model.max_output_tokens
                        ? `${model.max_output_tokens.toLocaleString()} max output`
                        : 'max output unknown'}
                    </div>
                  </div>
                  <SketchButton
                    variant="primary"
                    disabled={busy !== null}
                    onClick={() => void importPostAuthModel(model)}
                  >
                    {busy === `post-auth-model:${model.id}` ? 'Importing…' : 'Import'}
                  </SketchButton>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-4 text-sm font-body text-[var(--ink)]/70">
              No new models were advertised. Models already configured on this provider were left unchanged.
            </div>
          )}
        </WobblyCard>
      )}

      {showInstall && (
        <WobblyCard decoration="tape" className="p-5">
          <form onSubmit={install} className="space-y-4">
            <div>
              <h3 className="text-xl font-heading font-bold flex items-center gap-2">
                <Upload className="w-5 h-5 text-[var(--pen-blue)]" />
                Install Kinetix Extension Package
              </h3>
              <p className="text-sm font-body text-[var(--ink)]/75">
                Packages are installed disabled. Requested permissions must be reviewed before enablement.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <label className="block">
                <span className="block text-sm font-heading font-bold mb-1">Package</span>
                <input
                  type="file"
                  accept=".kxp,application/octet-stream"
                  onChange={(e) => setPackageFile(e.target.files?.[0] ?? null)}
                  className="w-full px-3 py-2 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-sm"
                />
              </label>
              <label className="block">
                <span className="block text-sm font-heading font-bold mb-1">Expected SHA-256 (optional)</span>
                <input
                  value={sha256}
                  onChange={(e) => setSha256(e.target.value)}
                  placeholder="64 hex characters"
                  className="w-full px-3 py-2 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-sm"
                />
              </label>
            </div>

            <label className="block">
              <span className="block text-sm font-heading font-bold mb-1">
                Trusted Ed25519 public keys (optional, one per line)
              </span>
              <textarea
                value={trustedKeys}
                onChange={(e) => setTrustedKeys(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-xs"
              />
            </label>

            <label className="flex items-start gap-2 text-sm font-body">
              <input
                type="checkbox"
                checked={allowUntrusted}
                onChange={(e) => setAllowUntrusted(e.target.checked)}
                className="mt-1"
              />
              <span>
                Allow an unsigned or untrusted signature. Use this only for packages you built or otherwise
                verified yourself.
              </span>
            </label>

            <div className="flex gap-2">
              <SketchButton type="submit" variant="primary" disabled={busy === 'install' || !packageFile} className="gap-2">
                <Upload className="w-4 h-4" />
                {busy === 'install' ? 'Installing…' : 'Install package'}
              </SketchButton>
              <SketchButton type="button" variant="secondary" onClick={() => setShowInstall(false)}>
                Cancel
              </SketchButton>
            </div>
          </form>
        </WobblyCard>
      )}

      {catalog.length > 0 && (
        <WobblyCard variant="muted" className="p-5">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div>
              <h3 className="text-xl font-heading font-bold">Discover</h3>
              <p className="text-sm font-body text-[var(--ink)]/70">
                Official catalog metadata is discovery-only. Installing a package still goes through
                Kinetix&apos;s normal package verification and permission-review flow.
              </p>
            </div>
            <SketchBadge variant="blue">Official catalog</SketchBadge>
          </div>

          <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-3">
            {catalog.map((entry) => {
              const installed = plugins.find((plugin) => plugin.id === entry.id);
              return (
                <div
                  key={entry.id}
                  className="p-4 border-2 border-[var(--ink)]/25 bg-[var(--surface)]"
                  style={{ borderRadius: '12px 9px 14px 10px / 9px 14px 9px 12px' }}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="font-heading font-bold">{entry.name}</div>
                      <div className="text-xs font-mono text-[var(--ink)]/55">{entry.publisher}</div>
                    </div>
                    <SketchBadge variant={installed ? 'green' : 'default'}>
                      {installed ? `Installed v${installed.version}` : `v${entry.latest_version}`}
                    </SketchBadge>
                  </div>

                  <p className="mt-2 text-sm font-body text-[var(--ink)]/75">{entry.description}</p>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {entry.capabilities.map((capability) => (
                      <code key={capability} className="text-xs bg-[var(--erased)] px-2 py-1">
                        {capability}
                      </code>
                    ))}
                  </div>
                  {entry.note && (
                    <p className="mt-3 text-xs font-body text-[var(--ink)]/60">{entry.note}</p>
                  )}
                  <div className="mt-3 flex items-center justify-between gap-3 flex-wrap">
                    <div className="text-xs font-mono text-[var(--ink)]/55">
                      Artifact: {entry.artifact_name}
                    </div>
                    {installed?.version === entry.latest_version ? (
                      <SketchBadge variant="green">Current</SketchBadge>
                    ) : entry.install_ready ? (
                      <SketchButton
                        variant="primary"
                        className="gap-2"
                        disabled={busy !== null}
                        onClick={() => void installFromCatalog(entry)}
                      >
                        <PackagePlus className="w-4 h-4" />
                        {busy === `catalog:${entry.id}`
                          ? 'Installing…'
                          : installed
                            ? `Update to v${entry.latest_version}`
                            : 'Install'}
                      </SketchButton>
                    ) : (
                      <SketchBadge variant="yellow">
                        {entry.trust_status === 'unavailable'
                          ? 'Trust unavailable'
                          : 'Discovery only'}
                      </SketchBadge>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </WobblyCard>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[minmax(280px,0.8fr)_minmax(0,2fr)] gap-6">
        <div className="space-y-3">
          {loading && plugins.length === 0 && (
            <WobblyCard variant="muted" className="p-5 text-sm font-mono">
              Loading plugins…
            </WobblyCard>
          )}
          {!loading && plugins.length === 0 && (
            <WobblyCard variant="muted" className="p-5">
              <h3 className="font-heading font-bold text-lg mb-1">No plugins installed</h3>
              <p className="text-sm font-body text-[var(--ink)]/75">
                Upload a <span className="font-mono">.kxp</span> package to start extending Kinetix.
              </p>
            </WobblyCard>
          )}
          {plugins.map((plugin) => (
            <button
              key={plugin.id}
              type="button"
              onClick={() => void selectPlugin(plugin.id)}
              className={`w-full text-left p-4 border-2 cursor-pointer transition-all ${selectedId === plugin.id
                ? 'bg-[var(--surface)] border-[var(--ink)] sketch-shadow-sm -translate-y-0.5'
                : 'bg-transparent border-[var(--ink)]/25 hover:border-[var(--ink)]/60 hover:bg-[var(--erased)]/40'
              }`}
              style={{ borderRadius: '14px 10px 16px 10px / 10px 16px 10px 14px' }}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="font-heading font-bold truncate">{plugin.name || plugin.id}</div>
                  <div className="font-mono text-[0.72rem] text-[var(--ink)]/55 truncate">{plugin.id}</div>
                </div>
                <SketchBadge variant={plugin.status === 'enabled' ? 'green' : 'yellow'} rotation="1deg">
                  {plugin.status}
                </SketchBadge>
              </div>
              <div className="mt-2 text-xs font-mono text-[var(--ink)]/70">
                v{plugin.version} · API {plugin.plugin_api_major}
              </div>
            </button>
          ))}
        </div>

        <div>
          {selected ? (
            <div className="space-y-5">
              <WobblyCard decoration="tack" className="p-5">
                <div className="flex flex-col md:flex-row md:items-start gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-2xl font-heading font-bold">{selected.name || selected.id}</h3>
                      <SketchBadge variant={selected.status === 'enabled' ? 'green' : 'yellow'}>
                        {selected.status}
                      </SketchBadge>
                      <SketchBadge variant={selected.signature === 'verified' ? 'green' : 'yellow'}>
                        {selected.signature}
                      </SketchBadge>
                    </div>
                    <div className="font-mono text-xs text-[var(--ink)]/60 mt-1 break-all">{selected.id}</div>
                    <div className="font-mono text-xs text-[var(--ink)]/60 mt-1 break-all">
                      SHA-256 {selected.sha256}
                    </div>
                  </div>
                  <div className="flex gap-2 flex-wrap">
                    <SketchButton
                      variant="secondary"
                      disabled={busy !== null}
                      onClick={() =>
                        void mutate(
                          'validate',
                          () => Kinetix.validatePlugin(selected.id),
                          'Plugin component validated successfully.',
                        )
                      }
                    >
                      Validate
                    </SketchButton>
                    {selected.status === 'enabled' ? (
                      <SketchButton
                        variant="secondary"
                        disabled={busy !== null}
                        onClick={() =>
                          void mutate(
                            'disable',
                            () => Kinetix.disablePlugin(selected.id),
                            'Plugin disabled.',
                          )
                        }
                        className="gap-2"
                      >
                        <PowerOff className="w-4 h-4" /> Disable
                      </SketchButton>
                    ) : (
                      <SketchButton
                        variant="primary"
                        disabled={busy !== null || !fullyApproved}
                        onClick={() =>
                          void mutate(
                            'enable',
                            () => Kinetix.enablePlugin(selected.id),
                            'Plugin enabled.',
                          )
                        }
                        className="gap-2"
                      >
                        <Power className="w-4 h-4" /> Enable
                      </SketchButton>
                    )}
                  </div>
                </div>
              </WobblyCard>

              {selected.integrations.length > 0 && (
                <WobblyCard decoration="tape" className="p-5">
                  <h4 className="text-lg font-heading font-bold mb-3">Integrations</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {selected.integrations.map((integration) => (
                      <div
                        key={integration.id}
                        className="p-4 border-2 border-[var(--ink)]/30 bg-[var(--surface)]"
                        style={{ borderRadius: '12px 9px 14px 10px / 9px 14px 9px 12px' }}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <div className="font-heading font-bold">{integration.name}</div>
                            <code className="text-[0.7rem] text-[var(--ink)]/55">{integration.id}</code>
                          </div>
                          <SketchBadge variant="blue">Integration</SketchBadge>
                        </div>
                        {integration.description && (
                          <p className="mt-2 text-sm font-body text-[var(--ink)]/75">
                            {integration.description}
                          </p>
                        )}
                        <div className="mt-3 flex flex-wrap gap-1">
                          {integration.provider_adapter && (
                            <code className="text-xs bg-[var(--erased)] px-2 py-1">
                              adapter:{integration.provider_adapter}
                            </code>
                          )}
                          {integration.credential_strategy && (
                            <code className="text-xs bg-[var(--erased)] px-2 py-1">
                              credential:{integration.credential_strategy}
                            </code>
                          )}
                          {integration.auth_flow && (
                            <code className="text-xs bg-[var(--erased)] px-2 py-1">
                              login:{integration.auth_flow}
                            </code>
                          )}
                          {integration.model_source && (
                            <code className="text-xs bg-[var(--erased)] px-2 py-1">
                              models:{integration.model_source}
                            </code>
                          )}
                          {integration.model_source_v2 && (
                            <code className="text-xs bg-[var(--erased)] px-2 py-1">
                              models:v2:{integration.model_source_v2}
                            </code>
                          )}
                        </div>

                        {selected.ui.actions
                          .filter((action) => action.integration === integration.id)
                          .map((action) => {
                            if (
                              action.kind !== 'auth' ||
                              !integration.auth_flow ||
                              !integration.credential_strategy
                            ) {
                              return null;
                            }

                            const compatibleProviders = providers.filter(
                              (provider) =>
                                provider.credentialPlugin ===
                                `plugin:${selected.id}/${integration.credential_strategy}`,
                            );

                            return (
                              <div key={action.id} className="mt-4 space-y-2">
                                {action.description && (
                                  <p className="text-xs font-body text-[var(--ink)]/65">
                                    {action.description}
                                  </p>
                                )}
                                {compatibleProviders.map((provider) => (
                                  <SketchButton
                                    key={provider.id}
                                    variant="primary"
                                    className="gap-2"
                                    disabled={busy !== null || selected.status !== 'enabled'}
                                    onClick={() =>
                                      void connectAccount(
                                        selected.id,
                                        integration.auth_flow!,
                                        provider.id,
                                      )
                                    }
                                  >
                                    <LogIn className="w-4 h-4" />
                                    {action.label} · {provider.name}
                                  </SketchButton>
                                ))}
                                {compatibleProviders.length === 0 &&
                                  (integration.provider ? (
                                    <div className="space-y-2">
                                      <div className="text-xs font-mono text-[var(--ink)]/55 break-all">
                                        {integration.provider.base_url}
                                      </div>
                                      <SketchButton
                                        variant="primary"
                                        className="gap-2"
                                        disabled={busy !== null || selected.status !== 'enabled'}
                                        onClick={() =>
                                          void setupAndConnect(
                                            selected.id,
                                            integration.id,
                                            integration.auth_flow!,
                                          )
                                        }
                                      >
                                        <LogIn className="w-4 h-4" />
                                        {busy === `setup:${integration.id}`
                                          ? 'Setting up…'
                                          : `Set up & ${action.label.toLowerCase()}`}
                                      </SketchButton>
                                      <p className="text-xs font-body text-[var(--ink)]/60">
                                        Kinetix will create the provider from the plugin&apos;s
                                        validated defaults, bind only this integration&apos;s
                                        capabilities, then start the authorization flow.
                                      </p>
                                    </div>
                                  ) : (
                                    <p className="text-xs font-body text-[var(--ink)]/60">
                                      Bind a provider&apos;s credential plugin to{' '}
                                      <code>
                                        plugin:{selected.id}/{integration.credential_strategy}
                                      </code>{' '}
                                      before using “{action.label}”.
                                    </p>
                                  ))}
                              </div>
                            );
                          })}
                      </div>
                    ))}
                  </div>
                </WobblyCard>
              )}

              {settings.length > 0 && (
                <WobblyCard className="p-5">
                  <div className="flex flex-col md:flex-row md:items-start gap-4">
                    <div className="flex-1">
                      <h4 className="text-lg font-heading font-bold">Settings</h4>
                      <p className="text-sm font-body text-[var(--ink)]/70">
                        These values are stored encrypted by Kinetix. Secret values are write-only in the dashboard.
                      </p>
                    </div>
                    <SketchButton
                      variant="primary"
                      disabled={busy !== null}
                      onClick={() => void saveSettings()}
                    >
                      {busy === 'settings' ? 'Saving…' : 'Save settings'}
                    </SketchButton>
                  </div>

                  <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {settings.map((setting) => (
                      <div key={setting.key} className="space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <label className="text-sm font-heading font-bold" htmlFor={`plugin-setting-${setting.key}`}>
                            {setting.label}
                            {setting.required && <span className="text-[var(--marker-red)]"> *</span>}
                          </label>
                          {setting.configured && !setting.required && (
                            <button
                              type="button"
                              className="text-xs font-mono underline text-[var(--ink)]/60 hover:text-[var(--ink)]"
                              disabled={busy !== null}
                              onClick={() => void clearSetting(setting.key)}
                            >
                              Clear
                            </button>
                          )}
                        </div>

                        {setting.kind === 'boolean' ? (
                          <label className="flex items-center gap-2 min-h-10">
                            <input
                              id={`plugin-setting-${setting.key}`}
                              type="checkbox"
                              checked={settingDrafts[setting.key] === true}
                              onChange={(e) =>
                                setSettingDrafts((current) => ({
                                  ...current,
                                  [setting.key]: e.target.checked,
                                }))
                              }
                            />
                            <span className="text-sm font-body">
                              {settingDrafts[setting.key] === true ? 'Enabled' : 'Disabled'}
                            </span>
                          </label>
                        ) : setting.kind === 'select' ? (
                          <select
                            id={`plugin-setting-${setting.key}`}
                            value={String(settingDrafts[setting.key] ?? '')}
                            onChange={(e) =>
                              setSettingDrafts((current) => ({
                                ...current,
                                [setting.key]: e.target.value,
                              }))
                            }
                            className="w-full px-3 py-2 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-sm"
                          >
                            {!setting.required && <option value="">—</option>}
                            {setting.options.map((option) => (
                              <option key={option} value={option}>{option}</option>
                            ))}
                          </select>
                        ) : (
                          <input
                            id={`plugin-setting-${setting.key}`}
                            type={setting.kind === 'secret' ? 'password' : 'text'}
                            value={String(settingDrafts[setting.key] ?? '')}
                            placeholder={
                              setting.kind === 'secret' && setting.configured
                                ? 'Configured — enter a new value to replace'
                                : undefined
                            }
                            onChange={(e) =>
                              setSettingDrafts((current) => ({
                                ...current,
                                [setting.key]: e.target.value,
                              }))
                            }
                            className="w-full px-3 py-2 bg-[var(--surface)] border-2 border-[var(--ink)] font-mono text-sm"
                          />
                        )}

                        {setting.description && (
                          <p className="text-xs font-body text-[var(--ink)]/60">{setting.description}</p>
                        )}
                        {setting.kind === 'secret' && setting.configured && (
                          <div className="text-xs font-mono text-[var(--success-text)]">Configured</div>
                        )}
                      </div>
                    ))}
                  </div>
                </WobblyCard>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <WobblyCard className="p-5">
                  <h4 className="text-lg font-heading font-bold flex items-center gap-2 mb-3">
                    <Box className="w-5 h-5 text-[var(--pen-blue)]" />
                    Capabilities
                  </h4>
                  <div className="space-y-2">
                    {selected.provides.length === 0 && (
                      <div className="text-sm text-[var(--ink)]/60">No capabilities reported.</div>
                    )}
                    {selected.provides.map((provided) => (
                      <div key={`${provided.capability}:${provided.name}`} className="flex items-center justify-between gap-3 border-b border-dashed border-[var(--ink)]/20 pb-2">
                        <span className="font-body text-sm">{prettyCapability(provided.capability)}</span>
                        <code className="text-xs break-all">{provided.name}</code>
                      </div>
                    ))}
                  </div>
                </WobblyCard>

                <WobblyCard variant="muted" className="p-5">
                  <h4 className="text-lg font-heading font-bold mb-3">Runtime limits</h4>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                    <dt className="text-[var(--ink)]/65">Memory</dt><dd className="font-mono">{selected.limits.memory}</dd>
                    <dt className="text-[var(--ink)]/65">Wall time</dt><dd className="font-mono">{selected.limits.wall_time_ms} ms</dd>
                    <dt className="text-[var(--ink)]/65">HTTP requests</dt><dd className="font-mono">{selected.limits.max_outbound_requests}</dd>
                    <dt className="text-[var(--ink)]/65">HTTP body</dt><dd className="font-mono">{selected.limits.max_http_body}</dd>
                    <dt className="text-[var(--ink)]/65">Storage</dt><dd className="font-mono">{selected.limits.storage}</dd>
                  </dl>
                </WobblyCard>
              </div>

              {detail?.packages && detail.packages.length > 0 && (
                <WobblyCard variant="muted" className="p-5">
                  <h4 className="text-lg font-heading font-bold mb-3">Retained packages</h4>
                  <div className="space-y-2">
                    {detail.packages.map((pkg) => {
                      const current = pkg.package_sha256 === selected.sha256;
                      return (
                        <div
                          key={pkg.package_sha256}
                          className="grid grid-cols-[auto_1fr_auto] gap-x-3 gap-y-1 border-b border-dashed border-[var(--ink)]/20 pb-2"
                        >
                          <SketchBadge variant={current ? 'green' : 'default'}>
                            v{pkg.version}
                          </SketchBadge>
                          <code className="text-xs break-all self-center">{pkg.package_sha256}</code>
                          {current ? (
                            <SketchBadge variant="green">Active</SketchBadge>
                          ) : (
                            <SketchButton
                              variant="secondary"
                              disabled={busy !== null}
                              onClick={() => void reviewRollback(selected.id, pkg.package_sha256)}
                            >
                              {busy === `preview:${pkg.package_sha256}` ? 'Reviewing…' : 'Review rollback'}
                            </SketchButton>
                          )}
                          <span className="text-xs text-[var(--ink)]/55">Stored package</span>
                          <code className="text-xs text-[var(--ink)]/55 break-all">{pkg.package_path}</code>
                          <span className="text-xs font-mono text-[var(--ink)]/55">{pkg.source}</span>
                        </div>
                      );
                    })}
                  </div>
                </WobblyCard>
              )}

              {rollbackPreview && (
                <WobblyCard decoration="tape" className="p-5">
                  <div className="flex flex-col md:flex-row md:items-start gap-4">
                    <div className="flex-1">
                      <h4 className="text-lg font-heading font-bold">
                        Review rollback: v{rollbackPreview.current_version} → v{rollbackPreview.target_version}
                      </h4>
                      <p className="text-sm font-body text-[var(--ink)]/70 mt-1">
                        The retained package has been re-hashed and its manifest revalidated for this preview.
                        Rollback will still recompile it, disable the plugin, and clear every approved permission.
                      </p>
                    </div>
                    <SketchBadge variant={rollbackPreview.signature === 'verified' ? 'green' : 'yellow'}>
                      {rollbackPreview.signature}
                    </SketchBadge>
                  </div>

                  <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div>
                      <h5 className="font-heading font-bold text-sm mb-2">Network hosts</h5>
                      {rollbackPreview.permission_diff.network_hosts.added.length === 0 &&
                      rollbackPreview.permission_diff.network_hosts.removed.length === 0 ? (
                        <p className="text-xs font-mono text-[var(--ink)]/55">No change</p>
                      ) : (
                        <div className="space-y-1 text-xs font-mono">
                          {rollbackPreview.permission_diff.network_hosts.added.map((value) => (
                            <div key={`host-add-${value}`}>+ {value}</div>
                          ))}
                          {rollbackPreview.permission_diff.network_hosts.removed.map((value) => (
                            <div key={`host-remove-${value}`}>− {value}</div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div>
                      <h5 className="font-heading font-bold text-sm mb-2">Credential scopes</h5>
                      {rollbackPreview.permission_diff.credential_scopes.added.length === 0 &&
                      rollbackPreview.permission_diff.credential_scopes.removed.length === 0 ? (
                        <p className="text-xs font-mono text-[var(--ink)]/55">No change</p>
                      ) : (
                        <div className="space-y-1 text-xs font-mono">
                          {rollbackPreview.permission_diff.credential_scopes.added.map((value) => (
                            <div key={`scope-add-${value}`}>+ {value}</div>
                          ))}
                          {rollbackPreview.permission_diff.credential_scopes.removed.map((value) => (
                            <div key={`scope-remove-${value}`}>− {value}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="mt-4 p-3 bg-[var(--erased)]/60 border border-dashed border-[var(--ink)]/25 text-sm">
                    Plaintext credential access:{' '}
                    <strong>
                      {rollbackPreview.permission_diff.credential_read.changed
                        ? `${rollbackPreview.permission_diff.credential_read.from ? 'enabled' : 'disabled'} → ${rollbackPreview.permission_diff.credential_read.to ? 'enabled' : 'disabled'}`
                        : rollbackPreview.permission_diff.credential_read.to
                          ? 'enabled (unchanged)'
                          : 'disabled (unchanged)'}
                    </strong>
                  </div>

                  <div className="mt-4 flex gap-2 flex-wrap">
                    <SketchButton
                      variant="primary"
                      disabled={busy !== null}
                      onClick={() => void confirmRollback()}
                    >
                      {busy === `rollback:${rollbackPreview.package_sha256}`
                        ? 'Restoring…'
                        : `Confirm rollback to v${rollbackPreview.target_version}`}
                    </SketchButton>
                    <SketchButton
                      variant="secondary"
                      disabled={busy !== null}
                      onClick={() => setRollbackPreview(null)}
                    >
                      Cancel
                    </SketchButton>
                  </div>
                </WobblyCard>
              )}

              <WobblyCard decoration="tape" className="p-5">
                <div className="flex flex-col md:flex-row md:items-start gap-4">
                  <div className="flex-1">
                    <h4 className="text-lg font-heading font-bold flex items-center gap-2">
                      <ShieldCheck className="w-5 h-5 text-[var(--pen-blue)]" />
                      Permission review
                    </h4>
                    <p className="text-sm font-body text-[var(--ink)]/75">
                      Approval is tied to the current manifest. A plugin should not be enabled until the requested
                      authority has been reviewed.
                    </p>
                  </div>
                  <SketchBadge variant={fullyApproved ? 'green' : 'yellow'}>
                    {fullyApproved ? 'Approved' : 'Approval required'}
                  </SketchBadge>
                </div>

                <div className="mt-4 space-y-3">
                  {requested.length === 0 && (
                    <div className="text-sm font-body text-[var(--ink)]/70">
                      This plugin requests no privileged host capabilities.
                    </div>
                  )}

                  {selected.permissions.network_hosts.length > 0 && (
                    <div className="p-3 border-2 border-[var(--ink)]/30 bg-[var(--surface)]">
                      <div className="flex items-center gap-2 font-heading font-bold text-sm">
                        <Network className="w-4 h-4" /> Network hosts
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {selected.permissions.network_hosts.map((host) => (
                          <code key={host} className="text-xs bg-[var(--erased)] px-2 py-1">{host}</code>
                        ))}
                      </div>
                    </div>
                  )}

                  {selected.permissions.credential_scopes.length > 0 && (
                    <div className="p-3 border-2 border-[var(--ink)]/30 bg-[var(--surface)]">
                      <div className="flex items-center gap-2 font-heading font-bold text-sm">
                        <KeyRound className="w-4 h-4" /> Credential scopes
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {selected.permissions.credential_scopes.map((scope) => (
                          <code key={scope} className="text-xs bg-[var(--erased)] px-2 py-1">{scope}</code>
                        ))}
                      </div>
                    </div>
                  )}

                  {selected.permissions.credential_read && (
                    <div className="p-3 border-2 border-[var(--marker-red)] bg-[var(--tint-red)]">
                      <div className="flex items-center gap-2 font-heading font-bold text-sm text-[var(--danger-text)]">
                        <AlertTriangle className="w-4 h-4" />
                        High risk: plaintext credential read
                      </div>
                      <p className="text-sm mt-1 text-[var(--danger-text)]">
                        The plugin can receive plaintext credentials inside its WASM memory for approved scopes.
                      </p>
                    </div>
                  )}
                </div>

                <div className="mt-4 flex gap-2 flex-wrap">
                  {!fullyApproved && (
                    <SketchButton
                      variant="primary"
                      disabled={busy !== null}
                      onClick={() =>
                        void mutate(
                          'approve',
                          () => Kinetix.approvePluginPermissions(selected.id),
                          'Current manifest permissions approved.',
                        )
                      }
                      className="gap-2"
                    >
                      <ShieldCheck className="w-4 h-4" /> Approve current permissions
                    </SketchButton>
                  )}
                  {permissions?.approved.map((grant) => (
                    <SketchButton
                      key={grant.permission}
                      variant="secondary"
                      disabled={busy !== null}
                      onClick={() =>
                        void mutate(
                          `revoke:${grant.permission}`,
                          () => Kinetix.revokePluginPermission(selected.id, grant.permission),
                          `Revoked ${grant.permission}; plugin is disabled until permissions are approved again.`,
                        )
                      }
                    >
                      Revoke {grant.permission}
                    </SketchButton>
                  ))}
                </div>
              </WobblyCard>

              <WobblyCard variant="muted" className="p-5">
                <div className="flex flex-col md:flex-row md:items-center gap-4">
                  <div className="flex-1">
                    <h4 className="font-heading font-bold">Remove plugin</h4>
                    <p className="text-sm font-body text-[var(--ink)]/70">
                      Removes the installed plugin and its host-managed plugin state.
                    </p>
                  </div>
                  <SketchButton
                    variant="danger"
                    disabled={busy !== null}
                    onClick={() => {
                      if (!window.confirm(`Remove plugin ${selected.id}? This also removes its plugin state.`)) {
                        return;
                      }
                      void removePlugin(selected.id);
                    }}
                    className="gap-2"
                  >
                    <Trash2 className="w-4 h-4" /> Remove
                  </SketchButton>
                </div>
              </WobblyCard>
            </div>
          ) : (
            <WobblyCard variant="muted" className="p-5 text-sm font-body text-[var(--ink)]/70">
              Select an installed plugin to inspect its capabilities and permissions.
            </WobblyCard>
          )}
        </div>
      </div>
    </div>
  );
};
