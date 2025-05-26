// gateway-service/.eslintrc.js
module.exports = {
  env: {
    node: true,
    es2021: true,
    jest: true
  },
  extends: [
    'standard',
    'plugin:jest/recommended'
  ],
  plugins: [
    'jest'
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  rules: {
    // General rules
    'no-console': 'off', // Allow console.log in server code
    'no-unused-vars': ['error', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_'
    }],
    'prefer-const': 'error',
    'no-var': 'error',
    
    // Style rules
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'comma-dangle': ['error', 'never'],
    'object-curly-spacing': ['error', 'always'],
    'array-bracket-spacing': ['error', 'never'],
    
    // Function rules
    'func-style': ['error', 'function', { allowArrowFunctions: true }],
    'prefer-arrow-callback': 'error',
    
    // Import rules
    'import/order': ['error', {
      groups: ['builtin', 'external', 'internal', 'parent', 'sibling', 'index'],
      'newlines-between': 'never'
    }],
    
    // Jest-specific rules
    'jest/no-disabled-tests': 'warn',
    'jest/no-focused-tests': 'error',
    'jest/no-identical-title': 'error',
    'jest/prefer-to-have-length': 'warn',
    'jest/valid-expect': 'error',
    'jest/expect-expect': 'error',
    'jest/no-test-prefixes': 'error',
    'jest/no-jasmine-globals': 'error',
    
    // Security rules
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error'
  },
  overrides: [
    {
      files: ['tests/**/*.js', '**/*.test.js', '**/*.spec.js'],
      env: {
        jest: true
      },
      rules: {
        'no-unused-expressions': 'off',
        'jest/expect-expect': ['error', {
          assertFunctionNames: ['expect', 'request.*.expect']
        }]
      }
    },
    {
      files: ['scripts/**/*.js', 'tests/load/**/*.js'],
      rules: {
        'no-console': 'off'
      }
    }
  ],
  globals: {
    testUtils: 'readonly',
    integrationTestUtils: 'readonly'
  }
};