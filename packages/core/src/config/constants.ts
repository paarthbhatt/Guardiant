/**
 * Guardiant Configuration
 */

export const CONFIG = {
  version: '0.1.0',
  name: 'Guardiant',
  description: 'Agentic Security Platform for Vibe-Coded Applications',

  // Database
  database: {
    defaultPath: 'guardiant.db',
  },

  // LLM
  llm: {
    providers: {
      anthropic: {
        name: 'Anthropic Claude',
        priority: 1,
        models: ['claude-sonnet-4-6', 'claude-3-5-sonnet-20241022'],
        defaultModel: 'claude-sonnet-4-6',
      },
      openrouter: {
        name: 'OpenRouter',
        priority: 2,
        models: ['anthropic/claude-sonnet-4', 'anthropic/claude-3.5-sonnet'],
        defaultModel: 'anthropic/claude-sonnet-4',
      },
      gemini: {
        name: 'Google Gemini',
        priority: 3,
        models: ['gemini-2.0-flash', 'gemini-1.5-pro'],
        defaultModel: 'gemini-2.0-flash',
      },
    },
    defaultMaxTokens: 4096,
    defaultTemperature: 0.7,
  },

  // Scanning
  scanning: {
    defaultTimeout: 600000, // 10 minutes
    defaultConcurrency: 4,
    stopOnCritical: false,
  },

  // Agents
  agents: {
    defaultEnabled: [
      'recon',
      'baas',
      'secrets',
      'auth',
      'injection',
      'supply_chain',
      'business_logic',
      'race_condition',
    ],
  },

  // Reporting
  reporting: {
    defaultFormat: 'markdown',
    defaultAudience: 'developer',
    formats: ['json', 'markdown', 'html', 'pdf'],
    audiences: ['executive', 'developer', 'security'],
  },
} as const;

export default CONFIG;