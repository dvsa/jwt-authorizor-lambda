import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  transform: {
    '\\.ts$': 'ts-jest',
    'node_modules/(iam-policy-generator|mock-jwks)': 'ts-jest',
  },
  testEnvironment: 'node',
  transformIgnorePatterns: ['node_modules\\/(?!(iam-policy-generator|mock-jwks))'],
  coverageDirectory: '<rootDir>/coverage/',
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 75,
      lines: 75,
      statements: 75,
    },
  },
  reporters: ['default', ['github-actions', { silent: false }]],
};

export default config;
