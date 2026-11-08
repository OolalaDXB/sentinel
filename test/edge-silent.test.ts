import { describe, expect, it, vi } from 'vitest';
import { must, withSentinel, type SentinelEvent } from '../src/index.ts';

describe('Sentinel: silent Edge failures', () => {
  it('captures 5xx responses without changing their status, body or headers', async () => {
    const events: SentinelEvent[] = [];
    const response = new Response('private business body', { status: 503, headers: { 'X-Business': 'ok' } });
    const wrapped = withSentinel(async () => response, {
      functionName: 'invoices',
      write: async (event) => { events.push(event); },
    });
    const returned = await wrapped(new Request('https://example.test/invoices?token=secret'));
    expect(returned).toBe(response);
    expect(returned.status).toBe(503);
    expect(returned.headers.get('X-Business')).toBe('ok');
    expect(await returned.text()).toBe('private business body');
    expect(events).toHaveLength(1);
    expect(events[0].url).toBe('/invoices');
    expect(events[0].context.function).toBe('invoices');
    expect(JSON.stringify(events)).not.toMatch(/private business body|token=secret/);
  });

  it('does not report ordinary 200/403 responses', async () => {
    const write = vi.fn();
    const options = { functionName: 'f', write };
    await withSentinel(async () => new Response('ok', { status: 200 }), options)(new Request('https://example.test/f'));
    await withSentinel(async () => new Response('forbidden', { status: 403 }), options)(new Request('https://example.test/f'));
    expect(write).not.toHaveBeenCalled();
  });

  it('keeps the response when the writer fails', async () => {
    const response = new Response('down', { status: 502 });
    const returned = await withSentinel(async () => response, {
      functionName: 'f', write: async () => { throw Error('writer failed'); },
    })(new Request('https://example.test/f'));
    expect(returned).toBe(response);
  });

  it('captures ignored result errors while preserving result identity', async () => {
    const events: SentinelEvent[] = [];
    const result = { error: { code: '42501', message: 'permission denied' }, data: null };
    const actual = await must(result, { functionName: 'save', write: async e => { events.push(e); } },
      new Request('https://example.test/save?token=secret'), { resource: 'orders', operation: 'update' });
    expect(actual).toBe(result);
    expect(events).toHaveLength(1);
    expect(events[0].error.type).toBe('permission_denied');
    expect(events[0].context).toMatchObject({ resource: 'orders', operation: 'update' });
    expect(events[0].url).toBe('/save');
  });

  it('does not treat an empty successful result as a failure', async () => {
    const write = vi.fn();
    const result = { data: [], error: null, count: 0 };
    expect(await must(result, { functionName: 'f', write })).toBe(result);
    expect(write).not.toHaveBeenCalled();
  });
});
