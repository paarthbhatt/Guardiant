import { describe, it, expect } from 'vitest';
import { TaintTracker, Source, Sink, Sanitizer } from '../analyzers/taint-tracker.js';

const sources: Source[] = [
  { name: 'req', property: 'body' },
  { name: 'req', property: 'query' },
];

const sinks: Sink[] = [
  { object: 'db', method: 'query' },
  { method: 'exec' }
];

const sanitizers: Sanitizer[] = [
  { name: 'escape' }
];

describe('TaintTracker', () => {
  it('should detect direct source to sink flow', () => {
    const code = `
      function handle(req, res) {
        db.query(req.body.id);
      }
    `;
    const tracker = new TaintTracker(code);
    const flows = tracker.analyzeFlows(sources, sinks, sanitizers);
    
    expect(flows).toHaveLength(1);
    expect(flows[0].sourceCode).toBe('req.body.id'); // based on AST parsing it might be req.body
    expect(flows[0].isSanitized).toBe(false);
  });

  it('should detect flow through variable assignment', () => {
    const code = `
      function handle(req, res) {
        const id = req.body.id;
        db.query(id);
      }
    `;
    const tracker = new TaintTracker(code);
    const flows = tracker.analyzeFlows(sources, sinks, sanitizers);
    
    expect(flows).toHaveLength(1);
    expect(flows[0].isSanitized).toBe(false);
  });

  it('should detect flow through template literals', () => {
    const code = `
      function handle(req, res) {
        const id = req.query.userId;
        db.query(\`SELECT * FROM users WHERE id = \${id}\`);
      }
    `;
    const tracker = new TaintTracker(code);
    const flows = tracker.analyzeFlows(sources, sinks, sanitizers);
    
    expect(flows).toHaveLength(1);
    expect(flows[0].isSanitized).toBe(false);
  });

  it('should detect when flow is sanitized', () => {
    const code = `
      function handle(req, res) {
        const id = req.body.id;
        db.query(escape(id));
      }
    `;
    const tracker = new TaintTracker(code);
    const flows = tracker.analyzeFlows(sources, sinks, sanitizers);
    
    expect(flows).toHaveLength(1);
    expect(flows[0].isSanitized).toBe(true);
  });
  
  it('should detect direct function sink', () => {
    const code = `
      function handle(req, res) {
        exec(req.query.cmd);
      }
    `;
    const tracker = new TaintTracker(code);
    const flows = tracker.analyzeFlows(sources, sinks, sanitizers);
    
    expect(flows).toHaveLength(1);
    expect(flows[0].isSanitized).toBe(false);
  });
});
