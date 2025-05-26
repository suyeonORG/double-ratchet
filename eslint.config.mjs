import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  js.configs.recommended,
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        project: './tsconfig.json',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      // TypeScript specific rules
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      
      // General code quality
      'no-console': 'off', // Allow console statements for now
      'no-debugger': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      
      // Turn off strict formatting for now
      'semi': 'off',
      'quotes': 'off',
      'comma-dangle': 'off',
      'no-case-declarations': 'off',
      
      // Turn off rules that conflict with TypeScript
      'no-undef': 'off',
      'no-unused-vars': 'off',
    },
  },
];