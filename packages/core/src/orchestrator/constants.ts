/**
 * Constants for the orchestrator
 */

import type { AgentId } from '@guardiant/shared';

/**
 * Agent execution order
 * First array contains agents that run in sequence
 * Second array contains agents that run in parallel after recon
 */
export const AGENT_EXECUTION_ORDER: AgentId[][] = [
  ['recon'], // Phase 1: Recon must run first
  ['baas', 'secrets', 'auth', 'injection', 'supply_chain', 'business_logic', 'race_condition'], // Phase 2: All others in parallel
];

/**
 * Agent dependencies
 * Each agent depends on recon completing first
 */
export const AGENT_DEPENDENCIES: Record<AgentId, AgentId[]> = {
  recon: [],
  baas: ['recon'],
  secrets: ['recon'],
  auth: ['recon'],
  injection: ['recon'],
  supply_chain: ['recon'],
  business_logic: ['recon'],
  race_condition: ['recon'],
};

/**
 * Agent priorities for job scheduling
 */
export const AGENT_PRIORITIES: Record<AgentId, 'critical' | 'high' | 'normal' | 'low'> = {
  recon: 'critical',
  baas: 'critical',
  secrets: 'critical',
  auth: 'high',
  injection: 'high',
  supply_chain: 'normal',
  business_logic: 'normal',
  race_condition: 'low',
};

/**
 * Default agent timeouts in milliseconds
 */
export const AGENT_TIMEOUTS: Record<AgentId, number> = {
  recon: 60000, // 1 minute
  baas: 120000, // 2 minutes
  secrets: 30000, // 30 seconds
  auth: 180000, // 3 minutes
  injection: 300000, // 5 minutes
  supply_chain: 60000, // 1 minute
  business_logic: 180000, // 3 minutes
  race_condition: 120000, // 2 minutes
};

/**
 * Default agent max retries
 */
export const AGENT_RETRIES: Record<AgentId, number> = {
  recon: 3,
  baas: 2,
  secrets: 3,
  auth: 2,
  injection: 1,
  supply_chain: 3,
  business_logic: 1,
  race_condition: 2,
};