/// <reference types="vitest" />

import vitestConfig from './tsconfig.json';

export default {
	...vitestConfig.compilerOptions,
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts'],
		coverage: {
			provider: 'v8',
			reporter: ['text', 'json', 'html'],
		},
	},
};
