import eslint from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/node_modules/**', 'dist/**'] },
  {
    files: ['src/**/*.ts'],
    extends: [eslint.configs.recommended, tseslint.configs.strictTypeChecked, tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      globals: globals.node,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // allow numbers and booleans in template strings, e.g. `${count} rows`
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true, allowBoolean: true }],
    },
  },
  {
    // node:test's describe/test return promises that the runner tracks itself
    files: ['src/**/*.test.ts'],
    rules: { '@typescript-eslint/no-floating-promises': 'off', '@typescript-eslint/no-non-null-assertion': 'off' },
  },
);
