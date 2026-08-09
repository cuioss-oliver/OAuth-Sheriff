/**
 * Mock implementation of Quarkus DevUI functionality
 *
 * This mock provides the DevUI JSON-RPC and notification functionality
 * used by JWT DevUI components.
 */

// Mock notification system
const createMockNotification = () => ({
  show: jest.fn(),
  hide: jest.fn(),
  update: jest.fn(),
});

// Mock DevUI object with JSON-RPC capabilities
export const devui = {
  // JSON-RPC client for calling backend services
  jsonRPC: {
    CuiJwtDevUI: {
      // Mock JWT validation status service
      getValidationStatus: jest.fn(() =>
        Promise.resolve({
          enabled: false,
          validatorPresent: false,
          status: 'BUILD_TIME',
          statusMessage: 'JWT validation status will be available at runtime',
        })
      ),

      // Mock JWKS status service
      getJwksStatus: jest.fn(() =>
        Promise.resolve({
          status: 'BUILD_TIME',
          message: 'JWKS endpoint status will be available at runtime',
        })
      ),

      // Mock configuration service
      getConfiguration: jest.fn(() =>
        Promise.resolve({
          enabled: false,
          healthEnabled: false,
          buildTime: true,
          message: 'Configuration details will be available at runtime',
        })
      ),

      // Mock token validation service
      validateToken: jest.fn(token => {
        if (!token || token.trim() === '') {
          return Promise.resolve({
            valid: false,
            error: 'Token is empty or null',
          });
        }
        return Promise.resolve({
          valid: false,
          error: 'Token validation not available at build time',
        });
      }),

      // Mock health info service
      getHealthInfo: jest.fn(() =>
        Promise.resolve({
          configurationValid: true,
          healthStatus: 'DOWN',
          message: 'Health information will be available at runtime',
        })
      ),
    },
  },

  // Mock notification API
  notifications: {
    info: jest.fn(() => createMockNotification()),
    success: jest.fn(() => createMockNotification()),
    warning: jest.fn(() => createMockNotification()),
    error: jest.fn(() => createMockNotification()),
  },

  // Mock theme utilities
  theme: {
    current: 'light',
    toggle: jest.fn(),
    set: jest.fn(),
    on: jest.fn(),
    off: jest.fn(),
  },

  // Mock router functionality
  router: {
    navigate: jest.fn(),
    currentPath: '/q/dev-ui',
    on: jest.fn(),
    off: jest.fn(),
  },

  // Mock storage utilities
  storage: {
    get: jest.fn((key, defaultValue) => defaultValue),
    set: jest.fn(),
    remove: jest.fn(),
    clear: jest.fn(),
  },

  // Mock utilities
  utils: {
    formatBytes: jest.fn(bytes => `${bytes} B`),
    formatDuration: jest.fn(ms => `${ms}ms`),
    formatTimestamp: jest.fn(timestamp => new Date(timestamp).toISOString()),
    copyToClipboard: jest.fn(() => Promise.resolve()),
    downloadFile: jest.fn(),
  },

  // Mock websocket functionality for real-time updates
  websocket: {
    connect: jest.fn(() => ({
      on: jest.fn(),
      off: jest.fn(),
      send: jest.fn(),
      close: jest.fn(),
    })),
  },
};

// Helper function to reset all mocks
export const resetDevUIMocks = () => {
  // Reset JWT validation status service to default
  devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockClear();
  devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
    enabled: false,
    validatorPresent: false,
    status: 'BUILD_TIME',
    statusMessage: 'JWT validation status will be available at runtime',
  });

  // Reset other services to default
  devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockClear();
  devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
    status: 'BUILD_TIME',
    message: 'JWKS endpoint status will be available at runtime',
  });

  devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockClear();
  devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
    enabled: false,
    healthEnabled: false,
    buildTime: true,
    message: 'Configuration details will be available at runtime',
  });

  devui.jsonRPC.CuiJwtDevUI.validateToken.mockClear();
  devui.jsonRPC.CuiJwtDevUI.validateToken.mockImplementation(token => {
    if (!token || token.trim() === '') {
      return Promise.resolve({
        valid: false,
        error: 'Token is empty or null',
      });
    }
    return Promise.resolve({
      valid: false,
      error: 'Token validation not available at build time',
    });
  });

  devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockClear();
  devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockResolvedValue({
    configurationValid: true,
    tokenValidatorAvailable: false,
    securityCounterAvailable: false,
    overallStatus: 'BUILD_TIME',
    message: 'Health information will be available at runtime',
  });

  Object.values(devui.notifications).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });

  Object.values(devui.theme).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });

  Object.values(devui.router).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });

  Object.values(devui.storage).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });

  Object.values(devui.utils).forEach(fn => {
    if (jest.isMockFunction(fn)) {
      fn.mockClear();
    }
  });
};

// Mock scenarios for different testing conditions
export const mockScenarios = {
  // Runtime environment with active JWT validation
  runtimeActive: () => {
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
      enabled: true,
      validatorPresent: true,
      status: 'ACTIVE',
      statusMessage: 'JWT validation is active and configured',
      securityEvents: {
        totalEvents: 150,
        errorEvents: 10,
        warningEvents: 25,
      },
    });

    devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
      status: 'CONFIGURED',
      issuers: {
        keycloak: {
          url: 'https://keycloak.example.com/auth/realms/master',
          jwksUrl: 'https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs',
          status: 'HEALTHY',
          lastCheck: new Date().toISOString(),
        },
      },
    });
  },

  // Runtime environment with issues
  runtimeWithIssues: () => {
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
      enabled: false,
      validatorPresent: false,
      status: 'INACTIVE',
      statusMessage: 'JWT validation is not available',
    });

    devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockResolvedValue({
      configurationValid: false,
      healthStatus: 'DOWN',
      message: 'JWT validation is disabled or misconfigured',
    });
  },

  // getConfiguration with a fully populated parser section (issuer namespace configured)
  configurationPropertyConfigured: () => {
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
      enabled: true,
      validatorPresent: true,
      status: 'ACTIVE',
      statusMessage: 'JWT validation is active and ready',
    });

    devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
      status: 'CONFIGURED',
      issuers: [
        {
          name: 'default',
          issuerUri: 'https://keycloak.example.com/auth/realms/master',
          jwksUri: 'configured',
          loaderStatus: 'OK',
          lastRefresh: 'N/A',
        },
      ],
    });

    devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
      enabled: true,
      logLevel: 'INFO',
      parser: {
        maxTokenSize: 8192,
        maxPayloadSize: 16_384,
        maxStringLength: 4096,
        clockSkewSeconds: 60,
        requireExpirationTime: true,
        requireNotBeforeTime: false,
        requireIssuedAtTime: true,
      },
      httpJwksLoader: {
        connectTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        readTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        sizeLimit: 8192,
      },
      issuers: {
        default: {
          issuerUri: 'https://keycloak.example.com/auth/realms/master',
          jwksUri: 'configured',
          clockSkewSeconds: 60,
        },
      },
    });
  },

  // getConfiguration when an externally-produced TokenValidator is observed: both
  // parserConfig-derived surfaces carry the unavailability marker and no issuer is exposed
  configurationExternalValidator: () => {
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
      enabled: true,
      validatorPresent: true,
      status: 'ACTIVE',
      statusMessage: 'JWT validation is active and ready',
    });

    devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
      status: 'EXTERNAL_VALIDATOR',
      issuers: [],
    });

    devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockResolvedValue({
      configurationValid: true,
      message: 'All JWT components are healthy and operational (EXTERNAL_VALIDATOR)',
      healthStatus: 'UP',
    });

    devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
      enabled: true,
      logLevel: 'INFO',
      parser: { status: 'unavailable (external validator)' },
      httpJwksLoader: {
        connectTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        readTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        sizeLimit: 'unavailable (external validator)',
      },
      issuers: {},
    });
  },

  // getConfiguration when nothing is observable at all
  configurationNotConfigured: () => {
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockResolvedValue({
      enabled: true,
      validatorPresent: false,
      status: 'NOT_CONFIGURED',
      statusMessage: 'No TokenValidator is configured',
    });

    devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockResolvedValue({
      status: 'NOT_CONFIGURED',
      issuers: [],
    });

    devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockResolvedValue({
      configurationValid: false,
      message: 'No TokenValidator is configured (NOT_CONFIGURED)',
      healthStatus: 'DOWN',
    });

    devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockResolvedValue({
      enabled: true,
      logLevel: 'INFO',
      parser: { status: 'unavailable (not configured)' },
      httpJwksLoader: {
        connectTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        readTimeoutSeconds: 'per-issuer (default: ~10s, from HttpHandler)',
        sizeLimit: 'unavailable (not configured)',
      },
      issuers: {},
    });
  },

  // Network error scenario
  networkError: () => {
    const networkError = new Error('Network error');
    devui.jsonRPC.CuiJwtDevUI.getValidationStatus.mockRejectedValue(networkError);
    devui.jsonRPC.CuiJwtDevUI.getJwksStatus.mockRejectedValue(networkError);
    devui.jsonRPC.CuiJwtDevUI.getConfiguration.mockRejectedValue(networkError);
    devui.jsonRPC.CuiJwtDevUI.getHealthInfo.mockRejectedValue(networkError);
  },
};

export default devui;
