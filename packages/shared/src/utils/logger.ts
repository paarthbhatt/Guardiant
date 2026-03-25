import winston from 'winston';
import { format } from 'winston';

/**
 * Log levels
 */
export type LogLevel = 'error' | 'warn' | 'info' | 'http' | 'verbose' | 'debug' | 'silly';

/**
 * Logger configuration
 */
export interface LoggerConfig {
  /** Minimum log level */
  level: LogLevel;
  /** Enable console output */
  console: boolean;
  /** Enable file output */
  file?: string;
  /** Enable JSON format */
  json: boolean;
  /** Include timestamps */
  timestamp: boolean;
  /** Include colors in console */
  colorize: boolean;
}

/**
 * Default logger configuration
 */
export const DEFAULT_LOGGER_CONFIG: LoggerConfig = {
  level: (process.env.LOG_LEVEL as LogLevel) ?? 'info',
  console: true,
  json: false,
  timestamp: true,
  colorize: true,
};

/**
 * Custom log format
 */
const customFormat = format.printf(({ level, message, timestamp, ...metadata }) => {
  const metaStr = Object.keys(metadata).length > 0 ? ` ${JSON.stringify(metadata)}` : '';
  return `${timestamp} [${level}]: ${message}${metaStr}`;
});

/**
 * Create a Winston logger instance
 */
export function createLogger(config: Partial<LoggerConfig> = {}): winston.Logger {
  const finalConfig = { ...DEFAULT_LOGGER_CONFIG, ...config };

  const transports: winston.transport[] = [];

  // Console transport
  if (finalConfig.console) {
    transports.push(
      new winston.transports.Console({
        format: format.combine(
          finalConfig.colorize ? format.colorize() : format.uncolorize(),
          finalConfig.timestamp ? format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }) : format.simple(),
          format.errors({ stack: true }),
          finalConfig.json ? format.json() : customFormat
        ),
      })
    );
  }

  // File transport
  if (finalConfig.file) {
    transports.push(
      new winston.transports.File({
        filename: finalConfig.file,
        format: format.combine(
          format.timestamp(),
          format.json()
        ),
      })
    );
  }

  return winston.createLogger({
    level: finalConfig.level,
    transports,
    exitOnError: false,
  });
}

/**
 * Default logger instance
 */
export const logger = createLogger();

/**
 * Create a child logger with context
 */
export function createChildLogger(parent: winston.Logger, context: string): winston.Logger {
  return parent.child({ context });
}

/**
 * Log levels type guard
 */
export function isValidLogLevel(level: string): level is LogLevel {
  return ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'].includes(level);
}

/**
 * Agent-specific logger
 */
export function createAgentLogger(agentId: string, scanId: string): winston.Logger {
  return createLogger().child({ agentId, scanId });
}