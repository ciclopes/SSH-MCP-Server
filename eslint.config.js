// Flat config for ESLint 10+.
// Goal: catch the exact bug class we just hit — variable shadowing — and a
// few other common issues, without being noisy about style.
import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        // Node built-ins we use at module top level.
        process: 'readonly',
        console: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        Buffer: 'readonly',
        URL: 'readonly',
      },
    },
    rules: {
      // The bug we just debugged was caused by `const resolve` inside the
      // Promise executor shadowing `resolve` imported from 'path'. The
      // original code did NOT use a `const` — it used the parameter name
      // directly: `return new Promise((resolve, reject) => { ...
      // resolve(...) ... path.resolve(...) ... })`. We caught it because
      // the eslint `no-shadow` rule with `hoist: 'all'` flags ANY
      // shadow, including parameter-vs-import.
      //
      // `builtinGlobals: true` also catches shadow of native globals like
      // `process`, `console`, etc.
      'no-shadow': ['error', { builtinGlobals: true, hoist: 'all' }],
      'no-redeclare': 'error',
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
      'no-undef': 'error',
      'no-unreachable': 'error',
      'no-fallthrough': 'error',
      'eqeqeq': ['error', 'smart'],
      'no-throw-literal': 'error',
      'prefer-const': 'warn',
      // Recommended rules we want to allow (turn off noisy ones).
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      globals: {
        // node:test globals.
        test: 'readonly',
        // node:assert/strict globals.
        assert: 'readonly',
        // Node.js builtins used in tests.
        spawn: 'readonly',
        mkdtempSync: 'readonly',
        readFileSync: 'readonly',
        writeFileSync: 'readonly',
        existsSync: 'readonly',
        statSync: 'readonly',
        rmSync: 'readonly',
        tmpdir: 'readonly',
        join: 'readonly',
        resolve: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': 'off',
      'no-undef': 'off',
      // Tests use `resolve` (from path), `spawn`, `test`, etc. as both
      // imports and identifiers (e.g. Promise resolve) — that's fine.
      'no-shadow': 'off',
    },
  },
];
