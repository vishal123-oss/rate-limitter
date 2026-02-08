module.exports = {
  env: {
    node: true,
    es2021: true,
    commonjs: true,
    jest: true
  },
  extends: 'eslint:recommended',
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  rules: {
    'indent': ['error', 2],
    'linebreak-style': ['error', 'unix'],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'no-console': 'off', // Allow console in server
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
  }
};
