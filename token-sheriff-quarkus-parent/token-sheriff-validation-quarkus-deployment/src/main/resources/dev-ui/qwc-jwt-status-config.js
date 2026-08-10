import { html, css, LitElement } from 'lit';
import { JsonRpc } from 'jsonrpc';

export class QwcJwtStatusConfig extends LitElement {
  jsonRpc = new JsonRpc('TokenSheriffDevUI');
  static styles = css`
    .container {
      max-width: 1200px;
      padding: 1rem;
    }

    .toolbar {
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1rem;
    }

    .refresh-button {
      padding: 0.5rem 1rem;
      border: none;
      border-radius: 4px;
      background-color: var(--lumo-primary-color);
      color: var(--lumo-primary-contrast-color);
      font-size: 0.875rem;
      cursor: pointer;
    }

    .refresh-button:hover {
      background-color: var(--lumo-primary-color-50pct);
    }

    .health-indicator {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.25rem 0.75rem;
      border-radius: 4px;
      font-size: 0.875rem;
      font-weight: 500;
    }

    .health-healthy {
      border: 1px solid var(--lumo-success-color-50pct);
      background-color: var(--lumo-success-color-10pct);
      color: var(--lumo-success-text-color);
    }

    .health-issues {
      border: 1px solid var(--lumo-error-color-50pct);
      background-color: var(--lumo-error-color-10pct);
      color: var(--lumo-error-text-color);
    }

    .health-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .health-dot.healthy {
      background-color: var(--lumo-success-color);
    }

    .health-dot.issues {
      background-color: var(--lumo-error-color);
    }

    .sections {
      display: grid;
      gap: 1.5rem;
    }

    .section {
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      background-color: var(--lumo-base-color);
    }

    .section-title {
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      color: var(--lumo-primary-text-color);
      font-size: 1.1rem;
      font-weight: 600;
      border-bottom: 1px solid var(--lumo-contrast-10pct);
    }

    .status-message {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1rem;
      color: var(--lumo-secondary-text-color);
    }

    .status-indicator {
      display: inline-block;
      flex-shrink: 0;
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }

    .status-active {
      background-color: var(--lumo-success-color);
      box-shadow: 0 0 8px var(--lumo-success-color);
    }

    .status-inactive {
      background-color: var(--lumo-error-color);
      box-shadow: 0 0 8px var(--lumo-error-color);
    }

    .status-unknown {
      background-color: var(--lumo-contrast-30pct);
    }

    .status-error {
      background-color: var(--lumo-error-color);
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }

    .metric-card {
      padding: 0.75rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
    }

    .metric-label {
      margin-bottom: 0.25rem;
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
    }

    .metric-value {
      color: var(--lumo-primary-text-color);
      font-size: 1.25rem;
      font-weight: 600;
    }

    .issuers-grid {
      display: grid;
      gap: 1rem;
    }

    .issuer-card {
      padding: 1rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 8px;
      background-color: var(--lumo-contrast-5pct);
    }

    .issuer-name {
      margin-bottom: 0.75rem;
      color: var(--lumo-primary-color);
      font-size: 1rem;
      font-weight: 600;
    }

    .issuer-details {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 0.75rem;
    }

    .detail-item {
      padding: 0.5rem;
      border-radius: 4px;
      background-color: var(--lumo-base-color);
    }

    .detail-label {
      margin-bottom: 0.25rem;
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
    }

    .detail-value {
      color: var(--lumo-primary-text-color);
      font-family: Monaco, Menlo, 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }

    .detail-value.not-configured {
      color: var(--lumo-error-text-color);
      font-style: italic;
    }

    .loader-status {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .config-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1rem;
    }

    .config-item {
      padding: 0.75rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
    }

    .config-label {
      margin-bottom: 0.25rem;
      color: var(--lumo-secondary-text-color);
      font-size: 0.875rem;
      font-weight: 500;
    }

    .config-value {
      color: var(--lumo-primary-text-color);
      font-family: Monaco, Menlo, 'Ubuntu Mono', monospace;
      font-size: 0.875rem;
      word-break: break-all;
    }

    .config-value.boolean {
      font-weight: 600;
    }

    .config-value.true {
      color: var(--lumo-success-text-color);
    }

    .config-value.false {
      color: var(--lumo-error-text-color);
    }

    .config-value.null {
      color: var(--lumo-secondary-text-color);
      font-style: italic;
    }

    .no-issuers {
      padding: 2rem;
      border: 1px solid var(--lumo-contrast-10pct);
      border-radius: 6px;
      background-color: var(--lumo-contrast-5pct);
      color: var(--lumo-secondary-text-color);
      text-align: center;
    }

    .loading {
      padding: 2rem;
      color: var(--lumo-secondary-text-color);
      text-align: center;
    }

    .error {
      padding: 1rem;
      border: 1px solid var(--lumo-error-color-50pct);
      border-radius: 6px;
      background-color: var(--lumo-error-color-10pct);
      color: var(--lumo-error-text-color);
    }
  `;

  static properties = {
    _validationStatus: { state: true },
    _jwksStatus: { state: true },
    _configuration: { state: true },
    _healthInfo: { state: true },
    _loading: { state: true },
    _error: { state: true },
  };

  constructor() {
    super();
    this._validationStatus = null;
    this._jwksStatus = null;
    this._configuration = null;
    this._healthInfo = null;
    this._loading = true;
    this._error = null;
  }

  connectedCallback() {
    super.connectedCallback();
    this._loadAllData();
    // Auto-refresh status data every 30 seconds
    this._refreshInterval = setInterval(() => this._loadAllData(), 30_000);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._refreshInterval) {
      clearInterval(this._refreshInterval);
    }
  }

  async _loadAllData() {
    try {
      this._loading = true;
      this._error = null;

      const [validationResponse, jwksResponse, configResponse, healthResponse] = await Promise.all([
        this.jsonRpc.getValidationStatus(),
        this.jsonRpc.getJwksStatus(),
        this.jsonRpc.getConfiguration(),
        this.jsonRpc.getHealthInfo(),
      ]);

      this._validationStatus = validationResponse.result;
      this._jwksStatus = jwksResponse.result;
      this._configuration = configResponse.result;
      this._healthInfo = healthResponse.result;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error loading status and configuration:', error);
      this._error = `Failed to load data: ${error.message}`;
    } finally {
      this._loading = false;
    }
  }

  _refresh() {
    this._loadAllData();
  }

  _formatValue(value) {
    if (value === null || value === undefined) {
      return { text: 'not set', className: 'null' };
    }
    if (typeof value === 'boolean') {
      return { text: value.toString(), className: `boolean ${value}` };
    }
    if (typeof value === 'string' && value.length === 0) {
      return { text: 'empty', className: 'null' };
    }
    return { text: value.toString(), className: '' };
  }

  _renderStatusOverview() {
    const status = this._validationStatus;
    const isActive = status.status === 'ACTIVE';

    return html`
      <div class="section" data-testid="status-overview-section">
        <h4 class="section-title">Status Overview</h4>

        <div class="status-message" data-testid="status-config-status-message">
          <div
            class="status-indicator ${isActive ? 'status-active' : 'status-inactive'}"
            data-testid="status-config-status-indicator"
          ></div>
          ${status.statusMessage || 'No status message available'}
        </div>

        <div class="metrics-grid">
          <div class="metric-card" data-testid="metric-enabled">
            <div class="metric-label">Validation Enabled</div>
            <div class="metric-value">${status.enabled ? 'Yes' : 'No'}</div>
          </div>

          <div class="metric-card" data-testid="metric-validator-present">
            <div class="metric-label">Validator Available</div>
            <div class="metric-value">${status.validatorPresent ? 'Yes' : 'No'}</div>
          </div>

          <div class="metric-card" data-testid="metric-overall-status">
            <div class="metric-label">Overall Status</div>
            <div class="metric-value">${status.status}</div>
          </div>

          ${
            status.securityEvents
              ? html`
                  <div class="metric-card">
                    <div class="metric-label">Total Security Events</div>
                    <div class="metric-value">${status.securityEvents.totalEvents}</div>
                  </div>

                  <div class="metric-card">
                    <div class="metric-label">Error Events</div>
                    <div class="metric-value">${status.securityEvents.errorEvents}</div>
                  </div>

                  <div class="metric-card">
                    <div class="metric-label">Warning Events</div>
                    <div class="metric-value">${status.securityEvents.warningEvents}</div>
                  </div>
                `
              : ''
          }
        </div>
      </div>
    `;
  }

  _renderIssuers() {
    const jwks = this._jwksStatus;
    const configIssuers = this._configuration?.issuers || {};

    return html`
      <div class="section" data-testid="status-config-issuers-section">
        <h4 class="section-title">Issuers</h4>
        ${
          jwks.issuers && jwks.issuers.length > 0
            ? html`
                <div class="issuers-grid">
                  ${jwks.issuers.map((issuer) => {
                    const configIssuer = configIssuers[issuer.name] || {};
                    return html`
                      <div class="issuer-card" data-testid="status-config-issuer-card">
                        <div class="issuer-name">${issuer.name}</div>
                        <div class="issuer-details">
                          <div class="detail-item">
                            <div class="detail-label">Issuer URI</div>
                            <div class="detail-value ${issuer.issuerUri === 'not configured' ? 'not-configured' : ''}">
                              ${issuer.issuerUri}
                            </div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">JWKS URI</div>
                            <div class="detail-value ${issuer.jwksUri === 'not configured' ? 'not-configured' : ''}">
                              ${issuer.jwksUri}
                            </div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">Loader Status</div>
                            <div class="loader-status">
                              <div class="status-indicator status-${issuer.loaderStatus.toLowerCase()}"></div>
                              <span class="detail-value">${issuer.loaderStatus}</span>
                            </div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">Last Refresh</div>
                            <div class="detail-value">${issuer.lastRefresh}</div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">Audience</div>
                            <div class="detail-value ${this._formatValue(configIssuer.audience).className}">
                              ${this._formatValue(configIssuer.audience).text}
                            </div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">Public Key Location</div>
                            <div class="detail-value ${this._formatValue(configIssuer.publicKeyLocation).className}">
                              ${this._formatValue(configIssuer.publicKeyLocation).text}
                            </div>
                          </div>

                          <div class="detail-item">
                            <div class="detail-label">Algorithm Preference</div>
                            <div class="detail-value">
                              ${
                                configIssuer.algorithmPreference
                                  ? configIssuer.algorithmPreference.join(', ')
                                  : 'default'
                              }
                            </div>
                          </div>
                        </div>
                      </div>
                    `;
                  })}
                </div>
              `
            : jwks.status === 'EXTERNAL_VALIDATOR'
              ? html`<div class="no-issuers">
                  No issuer configuration is exposed — an external validator is active and handling JWT validation.
                </div>`
              : html`<div class="no-issuers">No issuers configured. JWT validation will not be available.</div>`
        }
      </div>
    `;
  }

  /**
   * Reads the section-level unavailability marker the backend emits when no parser configuration is
   * observable, and maps it to the notice rendered in place of the parser-derived values.
   *
   * Both parser-derived surfaces — the Parser Configuration grid and the HTTP JWKS Loader's size
   * limit — consume this single predicate, so the symmetric peers cannot drift apart.
   *
   * @returns {string|null} the notice text, or `null` when the parser values are available
   */
  _parserUnavailableNotice() {
    const marker = this._configuration?.parser?.status;
    if (!marker) {
      return null;
    }
    return marker.includes('external validator') ? 'Not available — an external validator is in use' : 'Not configured';
  }

  _renderParserConfiguration() {
    const config = this._configuration;
    const notice = this._parserUnavailableNotice();
    if (notice) {
      return html`
        <div class="section" data-testid="status-config-parser-section">
          <h4 class="section-title">Parser Configuration</h4>
          <div class="config-grid">
            <div class="config-item">
              <div class="config-label">Parser Limits</div>
              <div class="config-value null" data-testid="status-config-parser-unavailable">${notice}</div>
            </div>
          </div>
        </div>
      `;
    }
    return html`
      <div class="section" data-testid="status-config-parser-section">
        <h4 class="section-title">Parser Configuration</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Max Token Size</div>
            <div class="config-value">${config.parser.maxTokenSize} bytes</div>
          </div>
          <div class="config-item">
            <div class="config-label">Clock Skew</div>
            <div class="config-value">${config.parser.clockSkewSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Expiration Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireExpirationTime).className}">
              ${this._formatValue(config.parser.requireExpirationTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Not Before Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireNotBeforeTime).className}">
              ${this._formatValue(config.parser.requireNotBeforeTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Issued At Time</div>
            <div class="config-value ${this._formatValue(config.parser.requireIssuedAtTime).className}">
              ${this._formatValue(config.parser.requireIssuedAtTime).text}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _renderHttpConfiguration() {
    const config = this._configuration;
    const notice = this._parserUnavailableNotice();
    return html`
      <div class="section" data-testid="status-config-http-section">
        <h4 class="section-title">HTTP JWKS Loader</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Connect Timeout</div>
            <div class="config-value">${config.httpJwksLoader.connectTimeoutSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Read Timeout</div>
            <div class="config-value">${config.httpJwksLoader.readTimeoutSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Size Limit</div>
            <div class="config-value ${notice ? 'null' : ''}" data-testid="status-config-http-size-limit">
              ${notice ? notice : html`${config.httpJwksLoader.sizeLimit} bytes`}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Cache TTL</div>
            <div class="config-value">${config.httpJwksLoader.cacheTtlSeconds} seconds</div>
          </div>
          <div class="config-item">
            <div class="config-label">Cache Size</div>
            <div class="config-value">${config.httpJwksLoader.cacheSize}</div>
          </div>
          <div class="config-item">
            <div class="config-label">Background Refresh</div>
            <div class="config-value ${this._formatValue(config.httpJwksLoader.backgroundRefreshEnabled).className}">
              ${this._formatValue(config.httpJwksLoader.backgroundRefreshEnabled).text}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _renderGeneralSettings() {
    const config = this._configuration;
    return html`
      <div class="section" data-testid="status-config-general-section">
        <h4 class="section-title">General Settings</h4>
        <div class="config-grid">
          <div class="config-item">
            <div class="config-label">Log Level</div>
            <div class="config-value">${config.logLevel}</div>
          </div>
        </div>
      </div>
    `;
  }

  render() {
    if (this._loading && !this._validationStatus) {
      return html`<div class="loading" data-testid="status-config-loading">Loading status and configuration...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error" data-testid="status-config-error">
          ${this._error}
          <button class="refresh-button" @click="${this._refresh}">Retry</button>
        </div>
      `;
    }

    if (!this._validationStatus || !this._configuration) {
      return html`<div class="loading">No data available</div>`;
    }

    const health = this._healthInfo;

    return html`
      <div class="container" data-testid="status-config-container">
        <div class="toolbar">
          ${
            health
              ? html`
                  <div
                    class="health-indicator ${health.overallStatus === 'HEALTHY' ? 'health-healthy' : 'health-issues'}"
                    data-testid="status-config-health-indicator"
                  >
                    <div class="health-dot ${health.overallStatus === 'HEALTHY' ? 'healthy' : 'issues'}"></div>
                    ${health.overallStatus === 'HEALTHY' ? 'Healthy' : 'Issues Detected'}
                  </div>
                `
              : ''
          }
          <button class="refresh-button" data-testid="status-config-refresh-button" @click="${this._refresh}">
            Refresh
          </button>
        </div>

        <div class="sections">
          ${this._renderStatusOverview()} ${this._renderIssuers()} ${this._renderParserConfiguration()}
          ${this._renderHttpConfiguration()} ${this._renderGeneralSettings()}
          ${
            health && health.issues && health.issues.length > 0
              ? html`
                  <div class="section">
                    <h4 class="section-title">Configuration Issues</h4>
                    <div style="color: var(--lumo-error-text-color);">
                      ${health.issues.map((issue) => html`<div style="margin-bottom: 0.5rem;">&bull; ${issue}</div>`)}
                    </div>
                  </div>
                `
              : ''
          }
        </div>
      </div>
    `;
  }
}

customElements.define('qwc-jwt-status-config', QwcJwtStatusConfig);
