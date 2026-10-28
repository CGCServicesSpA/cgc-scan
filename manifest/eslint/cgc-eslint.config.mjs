// Configuración de ESLint generada por CGC Scan. No carga configuración del
// proyecto (--no-config-lookup) y solo habilita reglas clasificadas en la
// tabla de categorías de design §8.3.
import security from 'eslint-plugin-security';
import tsParser from '@typescript-eslint/parser';

const rules = {
  'security/detect-eval-with-expression': 'error',
  'security/detect-child-process': 'error',
  'security/detect-non-literal-require': 'error',
  'security/detect-non-literal-regexp': 'warn',
  'security/detect-object-injection': 'warn',
  'security/detect-possible-timing-attacks': 'warn',
  'security/detect-pseudoRandomBytes': 'warn',
  'security/detect-bidi-characters': 'warn',
};

export default [
  {
    files: ['**/*.{js,jsx,mjs,cjs}'],
    plugins: { security },
    languageOptions: { ecmaVersion: 2024, sourceType: 'module' },
    rules,
  },
  {
    files: ['**/*.{ts,tsx}'],
    plugins: { security },
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2024,
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules,
  },
];
