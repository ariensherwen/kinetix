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
import { Kinetix, PluginDetail, PluginPermissionResponse, PluginSummary } from '../../lib/resources';
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
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<PluginDetail | null>(null);
  const [permissions, setPermissions] = useState<PluginPermissionResponse | null>(null);
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
    const [plugin, grants] = await Promise.all([
      Kinetix.plugin(id),
      Kinetix.pluginPermissions(id),
    ]);
    setDetail(plugin);
    setPermissions(grants);
  }, []);

  const refresh = useCallback(async (preferredId?: string | null) => {
    setLoading(true);
    try {
      const [rows, providerRows] = await Promise.all([
        Kinetix.plugins(),
        Kinetix.providers(),
      ]);
      setPlugins(rows);
      setProviders(providerRows);
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
      const query = params.toString();
      window.history.replaceState(
        null,
        '',
        `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`,
      );
    }

    void refresh(null);
    // Initial load only; later refreshes are explicit so selecting an item does
    // not re-run this effect through the selectedId dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectPlugin = async (id: string) => {
    setSelectedId(id);
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
      setNotice('Plugin removed.');
      await refresh(null);
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
                              auth:{integration.credential_strategy}
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
                        </div>

                        {integration.auth_flow && integration.credential_strategy && (
                          <div className="mt-4 space-y-2">
                            {providers
                              .filter(
                                (provider) =>
                                  provider.credentialPlugin ===
                                  `plugin:${selected.id}/${integration.credential_strategy}`,
                              )
                              .map((provider) => (
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
                                  Connect {provider.name}
                                </SketchButton>
                              ))}
                            {!providers.some(
                              (provider) =>
                                provider.credentialPlugin ===
                                `plugin:${selected.id}/${integration.credential_strategy}`,
                            ) && (
                              <p className="text-xs font-body text-[var(--ink)]/60">
                                Bind a provider's credential plugin to{' '}
                                <code>
                                  plugin:{selected.id}/{integration.credential_strategy}
                                </code>{' '}
                                before connecting an account.
                              </p>
                            )}
                          </div>
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
                    {detail.packages.map((pkg) => (
                      <div
                        key={pkg.package_sha256}
                        className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 border-b border-dashed border-[var(--ink)]/20 pb-2"
                      >
                        <SketchBadge variant={pkg.package_sha256 === selected.sha256 ? 'green' : 'default'}>
                          v{pkg.version}
                        </SketchBadge>
                        <code className="text-xs break-all self-center">{pkg.package_sha256}</code>
                        <span className="text-xs text-[var(--ink)]/55">Stored package</span>
                        <code className="text-xs text-[var(--ink)]/55 break-all">{pkg.package_path}</code>
                      </div>
                    ))}
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
