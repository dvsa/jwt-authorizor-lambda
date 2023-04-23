import type { Config } from 'jest';

const config: Config = {
  transform: {
    '\\.ts$': 'ts-jest',
  },
  testEnvironment: 'node',
  transformIgnorePatterns: ['<rootDir>/node_modules/'],
  coverageDirectory: '<rootDir>/coverage/',
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 75,
      lines: 75,
      statements: 75,
    },
  },
  reporters: ['default', 'github-actions'],
};

export default config;
