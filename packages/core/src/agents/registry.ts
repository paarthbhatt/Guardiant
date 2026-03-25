import type { BaseAgent, AgentId, AgentConfig } from '@guardiant/shared';
import { DEFAULT_AGENT_CONFIGS } from '@guardiant/shared';

/**
 * Agent registry for managing all available agents
 */
class AgentRegistry {
  private agents: Map<AgentId, BaseAgent> = new Map();
  private configs: Map<AgentId, AgentConfig> = new Map();

  /**
   * Register an agent
   */
  register(agent: BaseAgent, config?: Partial<AgentConfig>): void {
    if (this.agents.has(agent.id)) {
      throw new Error(`Agent ${agent.id} is already registered`);
    }

    this.agents.set(agent.id, agent);
    this.configs.set(agent.id, {
      ...DEFAULT_AGENT_CONFIGS[agent.id],
      ...config,
    });
  }

  /**
   * Get an agent by ID
   */
  get(id: AgentId): BaseAgent | undefined {
    return this.agents.get(id);
  }

  /**
   * Get agent configuration
   */
  getConfig(id: AgentId): AgentConfig | undefined {
    return this.configs.get(id);
  }

  /**
   * Get all registered agents
   */
  getAll(): BaseAgent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Get all agent IDs
   */
  getIds(): AgentId[] {
    return Array.from(this.agents.keys());
  }

  /**
   * Check if an agent is registered
   */
  has(id: AgentId): boolean {
    return this.agents.has(id);
  }

  /**
   * Get agents by priority
   */
  getByPriority(priority: 'critical' | 'high' | 'medium' | 'low'): BaseAgent[] {
    return this.getAll().filter(agent => {
      const config = this.configs.get(agent.id);
      return config?.priority === priority;
    });
  }

  /**
   * Get enabled agents
   */
  getEnabled(): BaseAgent[] {
    return this.getAll().filter(agent => {
      const config = this.configs.get(agent.id);
      return config?.enabled !== false;
    });
  }

  /**
   * Update agent configuration
   */
  updateConfig(id: AgentId, config: Partial<AgentConfig>): void {
    const currentConfig = this.configs.get(id);
    if (!currentConfig) {
      throw new Error(`Agent ${id} is not registered`);
    }
    this.configs.set(id, { ...currentConfig, ...config });
  }

  /**
   * Enable an agent
   */
  enable(id: AgentId): void {
    this.updateConfig(id, { enabled: true });
  }

  /**
   * Disable an agent
   */
  disable(id: AgentId): void {
    this.updateConfig(id, { enabled: false });
  }

  /**
   * Clear all registered agents
   */
  clear(): void {
    this.agents.clear();
    this.configs.clear();
  }
}

/**
 * Global agent registry instance
 */
export const agentRegistry = new AgentRegistry();

/**
 * Register all default agents
 */
export function registerDefaultAgents(): void {
  // Agents will be imported and registered here
  // This is called during initialization
}

/**
 * Create a new agent registry
 */
export function createAgentRegistry(): AgentRegistry {
  return new AgentRegistry();
}