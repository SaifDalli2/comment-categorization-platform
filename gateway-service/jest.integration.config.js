// gateway-service/jest.integration.config.js
module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/tests/integration/setup.js'],
  testMatch: [
    '<rootDir>/tests/integration/**/*.test.js',
    '<rootDir>/tests/integration/**/*.spec.js'
  ],
  moduleDirectories: ['node_modules', '<rootDir>'],
  testTimeout: 30000,
  verbose: true,
  maxWorkers: 1, // Run integration tests sequentially
  forceExit: true,
  clearMocks: true,
  restoreMocks: true
};