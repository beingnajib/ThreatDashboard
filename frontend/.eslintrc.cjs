module.exports = {
  root: true,
  env: { browser: true, es2022: true, node: true },
  extends: ["eslint:recommended", "plugin:react/recommended", "plugin:react/jsx-runtime", "plugin:react-hooks/recommended"],
  parserOptions: { ecmaVersion: "latest", sourceType: "module", ecmaFeatures: { jsx: true } },
  settings: { react: { version: "18.3" } },
  rules: { "react/prop-types": "off", "no-unused-vars": ["error", { argsIgnorePattern: "^_" }] },
  overrides: [{ files: ["**/*.test.jsx", "src/setupTests.js"], env: { node: true }, globals: { vi: "readonly", describe: "readonly", it: "readonly", expect: "readonly", beforeEach: "readonly", afterEach: "readonly", test: "readonly" } }],
};
