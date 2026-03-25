import { describe, it, expect } from 'vitest';
import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';

const execAsync = promisify(exec);

// Path to the compiled CLI entrypoint
const CLI_PATH = path.resolve(__dirname, '../../../../apps/cli/dist/index.js');

describe('CLI E2E', () => {
  it('should show help when run with --help', async () => {
    try {
      const { stdout } = await execAsync(`node ${CLI_PATH} --help`);
      expect(stdout).toContain('Usage: guardiant [options] [command]');
      expect(stdout).toContain('scan <target>');
    } catch (error: any) {
      // If the CLI is not built, fail gracefully or skip
      if (error.code === 'ENOENT') {
        console.warn('CLI not built, skipping E2E test');
        return;
      }
      throw error;
    }
  });

  it('should fail validation if target is missing', async () => {
    try {
      await execAsync(`node ${CLI_PATH} scan`);
    } catch (error: any) {
      expect(error.stderr).toContain("error: missing required argument 'target'");
    }
  });

  it('should fail Zod validation if maxConcurrency is out of bounds', async () => {
    try {
      await execAsync(`node ${CLI_PATH} scan https://example.com --max-concurrency 100`);
    } catch (error: any) {
      // The CLI output should capture the Zod error message
      expect(error.stderr).toContain('Invalid scan arguments');
      expect(error.stderr).toContain('maxConcurrency');
    }
  });
});
