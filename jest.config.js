module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts',
    '**/tests/**/*.test.ts'
  ],
  transform: {
    '^.+\.ts$': 'ts-jest',
  },
  // The source compiles to ESM and therefore imports its siblings with an
  // explicit `.js` extension, which is correct on disk but is not something
  // ts-jest's CommonJS transform can resolve. Mapping a relative `./x.js` back
  // to `./x` is what lets a unit test import a module that has relative
  // imports of its own, such as the transport.
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transformIgnorePatterns: [
    '/node_modules/(?!pretty-bytes)/'
  ],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
};