module.exports = {
    env: {
        browser: true,
        commonjs: true,
        es2021: true,
    },
    extends: 'standard',
    plugins: ['prettier'],
    extends: ['prettier'],
    overrides: [
        {
            env: {
                node: true,
            },
            files: ['.eslintrc.{js,cjs}'],
            parserOptions: {
                sourceType: 'script',
            },
        },
    ],
    parserOptions: {
        ecmaVersion: 'latest',
    },
    rules: {
        indent: ['error', 4, { SwitchCase: 1 }],
        'no-console': 1, // Means warning
        'prettier/prettier': [
            'error',
            {
                singleQuote: true,
                tabWidth: 4,
            },
        ],
    },
};
