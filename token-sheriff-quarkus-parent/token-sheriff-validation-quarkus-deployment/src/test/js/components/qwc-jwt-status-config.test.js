/**
 * Unit tests for QwcJwtStatusConfig merged component
 */

import { html, LitElement } from 'lit';
import { devui, mockScenarios, resetDevUIMocks } from '../mocks/devui.js';

/**
 * Flattens a Lit TemplateResult into the string it would render, interpolating every value and
 * recursing into nested templates. `undefined` and `null` values stringify verbatim, which is what
 * makes "the panel must never render the literal `undefined`" an assertable negative control.
 *
 * @param {unknown} value a TemplateResult, an array of them, or a plain interpolated value
 * @returns {string} the flattened markup
 */
const flattenTemplate = value => {
  if (Array.isArray(value)) {
    return value.map(entry => flattenTemplate(entry)).join('');
  }
  if (value && value.strings && value.values) {
    return value.strings.reduce(
      (accumulator, part, index) =>
        accumulator +
        part +
        (index < value.values.length ? flattenTemplate(value.values[index]) : ''),
      ''
    );
  }
  return String(value);
};

// Simplified component class for testing (mirrors the real component's logic)
class QwcJwtStatusConfig extends LitElement {
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
    this._refreshInterval = setInterval(() => this._loadAllData(), 30_000);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._refreshInterval) {
      clearInterval(this._refreshInterval);
      this._refreshInterval = undefined;
    }
  }

  async _loadAllData() {
    try {
      this._loading = true;
      this._error = null;
      this.requestUpdate();

      const [validation, jwks, config, health] = await Promise.all([
        devui.jsonRPC.CuiJwtDevUI.getValidationStatus(),
        devui.jsonRPC.CuiJwtDevUI.getJwksStatus(),
        devui.jsonRPC.CuiJwtDevUI.getConfiguration(),
        devui.jsonRPC.CuiJwtDevUI.getHealthInfo(),
      ]);

      this._validationStatus = validation;
      this._jwksStatus = jwks;
      this._configuration = config;
      this._healthInfo = health;
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error loading status and configuration:', error);
      this._error = `Failed to load data: ${error.message}`;
    } finally {
      this._loading = false;
      this.requestUpdate();
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

  render() {
    const result = this._doRender();
    this._lastRenderedResult = result.strings ? result.strings.join('') : result.toString();
    this._lastRenderedHtml = flattenTemplate(result);
    return result;
  }

  /**
   * Mirrors the real component's shared unavailability predicate: reads the section-level marker the
   * backend emits when no parser configuration is observable and maps it to the notice text.
   *
   * @returns {string|null} the notice text, or `null` when the parser values are available
   */
  _parserUnavailableNotice() {
    const marker = this._configuration?.parser?.status;
    if (!marker) {
      return null;
    }
    return marker.includes('external validator')
      ? 'Not available — an external validator is in use'
      : 'Not configured';
  }

  /**
   * The real backend always emits both keys; the guards keep the mirror usable for the pre-existing
   * tests that stub a bare `{ enabled: true }` configuration.
   *
   * @returns {Array<unknown>} the parser and HTTP sections that apply to the current configuration
   */
  _renderConfigSections() {
    const config = this._configuration;
    return [
      config.parser ? this._renderParserConfiguration() : '',
      config.httpJwksLoader ? this._renderHttpConfiguration() : '',
    ];
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
              <div class="config-value null" data-testid="status-config-parser-unavailable">
                ${notice}
              </div>
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
            <div
              class="config-value ${this._formatValue(config.parser.requireExpirationTime).className}"
            >
              ${this._formatValue(config.parser.requireExpirationTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Not Before Time</div>
            <div
              class="config-value ${this._formatValue(config.parser.requireNotBeforeTime).className}"
            >
              ${this._formatValue(config.parser.requireNotBeforeTime).text}
            </div>
          </div>
          <div class="config-item">
            <div class="config-label">Require Issued At Time</div>
            <div
              class="config-value ${this._formatValue(config.parser.requireIssuedAtTime).className}"
            >
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
            <div
              class="config-value ${notice ? 'null' : ''}"
              data-testid="status-config-http-size-limit"
            >
              ${notice ? notice : html`${config.httpJwksLoader.sizeLimit} bytes`}
            </div>
          </div>
        </div>
      </div>
    `;
  }

  _doRender() {
    if (this._loading && !this._validationStatus) {
      return html`<div class="loading">Loading status and configuration...</div>`;
    }

    if (this._error) {
      return html`
        <div class="error">
          ${this._error}
          <button class="refresh-button" @click="${this._refresh}">Retry</button>
        </div>
      `;
    }

    if (!this._validationStatus || !this._configuration) {
      return html`<div class="loading">No data available</div>`;
    }

    const status = this._validationStatus;
    const isActive = status.status === 'ACTIVE';
    const health = this._healthInfo;

    return html`
      <div class="container">
        <div class="toolbar">
          ${
            health
              ? html`
                  <div
                    class="health-indicator ${
                      health.overallStatus === 'HEALTHY' ? 'health-healthy' : 'health-issues'
                    }"
                  >
                    ${health.overallStatus === 'HEALTHY' ? 'Healthy' : 'Issues Detected'}
                  </div>
                `
              : ''
          }
          <button class="refresh-button" @click="${this._refresh}">Refresh</button>
        </div>

        <div class="sections">
          <div class="section">
            <h4 class="section-title">Status Overview</h4>
            <div class="status-message">
              <div class="status-indicator ${isActive ? 'status-active' : 'status-inactive'}"></div>
              ${status.statusMessage || 'No status message available'}
            </div>
            <div class="metrics-grid">
              <div class="metric-card">
                <div class="metric-label">Validation Enabled</div>
                <div class="metric-value">${status.enabled ? 'Yes' : 'No'}</div>
              </div>
              <div class="metric-card">
                <div class="metric-label">Validator Available</div>
                <div class="metric-value">${status.validatorPresent ? 'Yes' : 'No'}</div>
              </div>
              <div class="metric-card">
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
          ${this._renderConfigSections()}
        </div>
      </div>
    `;
  }
}

describe('QwcJwtStatusConfig', () => {
  let component;

  beforeEach(async () => {
    resetDevUIMocks();
    component = new QwcJwtStatusConfig();
    component.connectedCallback();
    await waitForComponentUpdate(component);
  });

  afterEach(() => {
    if (component && component._refreshInterval) {
      clearInterval(component._refreshInterval);
    }
  });

  describe('Component Initialization', () => {
    it('should create component with default properties', () => {
      expect(component).toBeDefined();
      expect(component._loading).toBe(false);
      expect(component._error).toBeNull();
    });

    it('should have correct static properties', () => {
      expect(QwcJwtStatusConfig.properties).toBeDefined();
      expect(QwcJwtStatusConfig.properties._validationStatus).toEqual({ state: true });
      expect(QwcJwtStatusConfig.properties._jwksStatus).toEqual({ state: true });
      expect(QwcJwtStatusConfig.properties._configuration).toEqual({ state: true });
      expect(QwcJwtStatusConfig.properties._healthInfo).toEqual({ state: true });
      expect(QwcJwtStatusConfig.properties._loading).toEqual({ state: true });
      expect(QwcJwtStatusConfig.properties._error).toEqual({ state: true });
    });

    it('should call all four JSON-RPC methods on connection', async () => {
      expect(devui.jsonRPC.CuiJwtDevUI.getValidationStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getHealthInfo).toHaveBeenCalled();
    });
  });

  describe('Loading State', () => {
    it('should show loading message initially', async () => {
      component._validationStatus = null;
      component._loading = true;
      component._error = null;
      component.render();
      await waitForComponentUpdate(component);

      expect(component).toHaveRenderedContent('Loading status and configuration...');
    });

    it('should have loading class when loading', async () => {
      component._validationStatus = null;
      component._loading = true;
      component._error = null;
      component.render();
      await waitForComponentUpdate(component);

      expect(component).toHaveShadowClass('loading');
    });
  });

  describe('Error State', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      mockScenarios.networkError();

      component = new QwcJwtStatusConfig();
      component.connectedCallback();
      await waitForComponentUpdate(component);
    });

    it('should display error message', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Failed to load data: Network error');
    });

    it('should have error class when error occurs', async () => {
      component.render();
      expect(component).toHaveShadowClass('error');
    });

    it('should show retry button in error state', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Retry');
    });

    it('should retry loading when retry button is clicked', async () => {
      resetDevUIMocks();
      component._refresh();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getValidationStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getHealthInfo).toHaveBeenCalled();
    });
  });

  describe('Build Time Status Display', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      await component._loadAllData();
      await waitForComponentUpdate(component);
    });

    it('should display build time status correctly', async () => {
      component.render();
      expect(component).toHaveRenderedContent('JWT validation status will be available at runtime');
      expect(component).toHaveRenderedContent('BUILD_TIME');
    });

    it('should show inactive status indicator for build time', async () => {
      component.render();
      expect(component).toHaveShadowClass('status-inactive');
      expect(component).not.toHaveShadowClass('status-active');
    });

    it('should display correct metric values for build time', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Validation Enabled');
      expect(component).toHaveRenderedContent('No');
      expect(component).toHaveRenderedContent('Validator Available');
      expect(component).toHaveRenderedContent('Overall Status');
    });
  });

  describe('Runtime Active Status Display', () => {
    beforeEach(async () => {
      mockScenarios.runtimeActive();
      await component._loadAllData();
      await waitForComponentUpdate(component);
    });

    it('should display active status correctly', async () => {
      component.render();
      expect(component).toHaveRenderedContent('JWT validation is active and configured');
      expect(component).toHaveRenderedContent('ACTIVE');
    });

    it('should show active status indicator', async () => {
      component.render();
      expect(component).toHaveShadowClass('status-active');
      expect(component).not.toHaveShadowClass('status-inactive');
    });

    it('should display security events when available', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Total Security Events');
      expect(component).toHaveRenderedContent('150');
    });

    it('should show enabled validation metrics', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Yes');
    });
  });

  describe('Runtime Inactive Status Display', () => {
    beforeEach(async () => {
      mockScenarios.runtimeWithIssues();
      await component._loadAllData();
      await waitForComponentUpdate(component);
    });

    it('should display inactive status correctly', async () => {
      component.render();
      expect(component).toHaveRenderedContent('JWT validation is not available');
      expect(component).toHaveRenderedContent('INACTIVE');
    });

    it('should show inactive status indicator', async () => {
      component.render();
      expect(component).toHaveShadowClass('status-inactive');
      expect(component).not.toHaveShadowClass('status-active');
    });
  });

  describe('Refresh Functionality', () => {
    it('should have refresh button', async () => {
      await waitForComponentUpdate(component);
      component.render();
      expect(component).toHaveRenderedContent('Refresh');
    });

    it('should reload all data when refresh is clicked', async () => {
      await waitForComponentUpdate(component);

      devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockClear();
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockClear();
      devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockClear();
      devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockClear();

      component._refresh();
      await waitForComponentUpdate(component);

      expect(devui.jsonRPC.CuiJwtDevUI.getValidationStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getConfiguration).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getHealthInfo).toHaveBeenCalled();
    });

    it('should setup auto-refresh interval on connection', () => {
      expect(component._refreshInterval).toBeDefined();
      expect(typeof component._refreshInterval).toBe('number');
    });

    it('should clear interval on disconnection', () => {
      component.disconnectedCallback();
      expect(component._refreshInterval).toBeUndefined();
    });
  });

  describe('_formatValue Helper', () => {
    it('should handle null values', () => {
      const result = component._formatValue(null);
      expect(result.text).toBe('not set');
      expect(result.className).toBe('null');
    });

    it('should handle undefined values', () => {
      const result = component._formatValue(undefined);
      expect(result.text).toBe('not set');
      expect(result.className).toBe('null');
    });

    it('should handle boolean true', () => {
      const result = component._formatValue(true);
      expect(result.text).toBe('true');
      expect(result.className).toBe('boolean true');
    });

    it('should handle boolean false', () => {
      const result = component._formatValue(false);
      expect(result.text).toBe('false');
      expect(result.className).toBe('boolean false');
    });

    it('should handle empty strings', () => {
      const result = component._formatValue('');
      expect(result.text).toBe('empty');
      expect(result.className).toBe('null');
    });

    it('should handle regular strings', () => {
      const result = component._formatValue('some-value');
      expect(result.text).toBe('some-value');
      expect(result.className).toBe('');
    });

    it('should handle numbers', () => {
      const result = component._formatValue(42);
      expect(result.text).toBe('42');
      expect(result.className).toBe('');
    });
  });

  describe('Component Lifecycle', () => {
    it('should load all data on connected callback', async () => {
      const newComponent = new QwcJwtStatusConfig();

      devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockClear();
      devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockClear();

      newComponent.connectedCallback();
      await waitForComponentUpdate(newComponent);

      expect(devui.jsonRPC.CuiJwtDevUI.getValidationStatus).toHaveBeenCalled();
      expect(devui.jsonRPC.CuiJwtDevUI.getJwksStatus).toHaveBeenCalled();

      if (newComponent._refreshInterval) {
        clearInterval(newComponent._refreshInterval);
      }
    });

    it('should handle disconnection when no interval is set', () => {
      const newComponent = new QwcJwtStatusConfig();
      newComponent._refreshInterval = undefined;
      expect(() => newComponent.disconnectedCallback()).not.toThrow();
      expect(newComponent._refreshInterval).toBeUndefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle network errors gracefully', async () => {
      const networkError = new Error('Network error');
      devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockRejectedValue(networkError);

      await component._loadAllData();
      await waitForComponentUpdate(component);

      expect(component._error).toContain('Failed to load data: Network error');
      expect(component._loading).toBe(false);
    });

    it('should log errors to console', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const networkError = new Error('Test error');
      devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockRejectedValue(networkError);

      await component._loadAllData();

      expect(consoleSpy).toHaveBeenCalledWith(
        'Error loading status and configuration:',
        networkError
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Component Rendering', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      await component._loadAllData();
      await waitForComponentUpdate(component);
    });

    it('should render container structure', async () => {
      component.render();
      expect(component).toHaveShadowClass('container');
      expect(component).toHaveShadowClass('toolbar');
      expect(component).toHaveShadowClass('sections');
    });

    it('should render status overview section', async () => {
      component.render();
      expect(component).toHaveRenderedContent('Status Overview');
      expect(component).toHaveShadowClass('metrics-grid');
    });

    it('should render metric cards', async () => {
      component.render();
      expect(component).toHaveShadowClass('metric-card');
    });

    it('should render status indicator', async () => {
      component.render();
      expect(component).toHaveShadowClass('status-indicator');
    });
  });

  describe('Enhanced Status Display Coverage', () => {
    it('should display status message when available', () => {
      component._loading = false;
      component._validationStatus = {
        status: 'ACTIVE',
        statusMessage: 'Custom validation message',
        enabled: true,
        validatorPresent: true,
      };
      component._configuration = { enabled: true };
      component.render();

      expect(component).toHaveRenderedContent('Custom validation message');
    });

    it('should display fallback message when no status message', () => {
      component._loading = false;
      component._validationStatus = {
        status: 'ACTIVE',
        statusMessage: null,
        enabled: true,
        validatorPresent: true,
      };
      component._configuration = { enabled: true };
      component.render();

      expect(component).toHaveRenderedContent('No status message available');
    });

    it('should render complete security events section', () => {
      component._loading = false;
      component._validationStatus = {
        status: 'ACTIVE',
        enabled: true,
        validatorPresent: true,
        securityEvents: {
          totalEvents: 100,
          errorEvents: 5,
          warningEvents: 10,
        },
      };
      component._configuration = { enabled: true };
      component.render();

      expect(component).toHaveRenderedContent('Total Security Events');
      expect(component).toHaveRenderedContent('100');
      expect(component).toHaveRenderedContent('Error Events');
      expect(component).toHaveRenderedContent('5');
      expect(component).toHaveRenderedContent('Warning Events');
      expect(component).toHaveRenderedContent('10');
    });

    it('should not render security events when not present', () => {
      component._loading = false;
      component._validationStatus = {
        status: 'INACTIVE',
        enabled: false,
        validatorPresent: false,
        securityEvents: null,
      };
      component._configuration = { enabled: false };
      component.render();

      expect(component).not.toHaveRenderedContent('Total Security Events');
      expect(component).not.toHaveRenderedContent('Error Events');
    });
  });

  describe('Parser Configuration — PROPERTY_CONFIGURED', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      mockScenarios.configurationPropertyConfigured();
      await component._loadAllData();
      await waitForComponentUpdate(component);
      component.render();
    });

    it('should render the full parser grid with the real values', () => {
      expect(component._lastRenderedHtml).toContain('Max Token Size');
      expect(component._lastRenderedHtml).toContain('8192 bytes');
      expect(component._lastRenderedHtml).toContain('Clock Skew');
      expect(component._lastRenderedHtml).toContain('60 seconds');
    });

    it('should render the HTTP size limit from the parser configuration', () => {
      expect(component._lastRenderedHtml).toContain('Size Limit');
      expect(component._lastRenderedHtml).toContain('8192 bytes');
    });

    it('should render no unavailability notice', () => {
      expect(component._parserUnavailableNotice()).toBeNull();
      expect(component._lastRenderedHtml).not.toContain('status-config-parser-unavailable');
      expect(component._lastRenderedHtml).not.toContain('undefined');
    });
  });

  describe('Parser Configuration — EXTERNAL_VALIDATOR', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      mockScenarios.configurationExternalValidator();
      await component._loadAllData();
      await waitForComponentUpdate(component);
      component.render();
    });

    it('should render the external-validator notice in place of the parser grid', () => {
      expect(component._parserUnavailableNotice()).toBe(
        'Not available — an external validator is in use'
      );
      expect(component._lastRenderedHtml).toContain(
        'Not available — an external validator is in use'
      );
      expect(component._lastRenderedHtml).not.toContain('Max Token Size');
    });

    it('should render the same notice for the symmetric sizeLimit peer', () => {
      expect(component._lastRenderedHtml).toContain('status-config-http-size-limit');
      expect(component._lastRenderedHtml).not.toContain('undefined bytes');
    });

    it('should keep emitting the parser and HTTP section containers', () => {
      expect(component._lastRenderedHtml).toContain('data-testid="status-config-parser-section"');
      expect(component._lastRenderedHtml).toContain('data-testid="status-config-http-section"');
    });

    it('should never render the literal undefined', () => {
      expect(component._lastRenderedHtml).not.toContain('undefined');
    });
  });

  describe('Parser Configuration — NOT_CONFIGURED', () => {
    beforeEach(async () => {
      resetDevUIMocks();
      mockScenarios.configurationNotConfigured();
      await component._loadAllData();
      await waitForComponentUpdate(component);
      component.render();
    });

    it('should render the not-configured notice in place of the parser grid', () => {
      expect(component._parserUnavailableNotice()).toBe('Not configured');
      expect(component._lastRenderedHtml).toContain('Not configured');
      expect(component._lastRenderedHtml).not.toContain('Max Token Size');
    });

    it('should keep emitting the parser and HTTP section containers', () => {
      expect(component._lastRenderedHtml).toContain('data-testid="status-config-parser-section"');
      expect(component._lastRenderedHtml).toContain('data-testid="status-config-http-section"');
    });

    it('should never render the literal undefined', () => {
      expect(component._lastRenderedHtml).not.toContain('undefined');
    });
  });

  describe('No Data Available State', () => {
    it('should show no data message when validation status is missing', () => {
      component._loading = false;
      component._validationStatus = null;
      component._configuration = { enabled: true };
      component.render();

      expect(component).toHaveRenderedContent('No data available');
    });

    it('should show no data message when configuration is missing', () => {
      component._loading = false;
      component._validationStatus = { status: 'ACTIVE', enabled: true };
      component._configuration = null;
      component.render();

      expect(component).toHaveRenderedContent('No data available');
    });
  });
});
