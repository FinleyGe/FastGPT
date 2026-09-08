import { describe, expect, it, vi } from 'vitest';
import {
  FASTGPT_WEB_REQUEST_HEADER,
  isAllowedOrigin,
  isAllowedReferer,
  isValidWebRequest,
  parseAllowedOrigins,
  shouldValidateWebRequest,
  checkCsrf
} from '@fastgpt/next/middle/csrf';

const request = (
  headers: Record<string, string>,
  url = '/api/core/app/update',
  method = 'GET'
) => ({
  headers,
  method,
  url
});

describe('web request CSRF guard', () => {
  it('parses and validates configured Origin allowlists', () => {
    const allowedOrigins = parseAllowedOrigins(
      ' https://app.example.com, ,https://admin.example.com '
    );

    expect(allowedOrigins).toEqual(['https://app.example.com', 'https://admin.example.com']);
    expect(
      isAllowedOrigin('https://app.example.com', 'https://fastgpt.example.com', allowedOrigins)
    ).toBe(true);
    expect(
      isAllowedOrigin('https://fastgpt.example.com', 'https://fastgpt.example.com', allowedOrigins)
    ).toBe(true);
    expect(
      isAllowedOrigin('https://evil.example.com', 'https://fastgpt.example.com', allowedOrigins)
    ).toBe(false);
    expect(isAllowedOrigin('https://evil.example.com', 'https://fastgpt.example.com')).toBe(true);
    expect(isAllowedOrigin(undefined, 'https://fastgpt.example.com', allowedOrigins)).toBe(true);
    expect(
      isAllowedReferer(
        'https://app.example.com/settings',
        'https://fastgpt.example.com',
        allowedOrigins
      )
    ).toBe(true);
    expect(
      isAllowedReferer(
        'https://evil.example.com/settings',
        'https://fastgpt.example.com',
        allowedOrigins
      )
    ).toBe(false);
    expect(isAllowedReferer(undefined, 'https://fastgpt.example.com', allowedOrigins)).toBe(false);
  });

  it('requires the Web header for Cookie-authenticated requests', () => {
    const req = request({ cookie: 'fastgpt_token=session-1' });

    expect(shouldValidateWebRequest(req)).toBe(true);
    expect(isValidWebRequest(req)).toBe(false);
    expect(
      isValidWebRequest(
        request({
          cookie: 'fastgpt_token=session-1',
          [FASTGPT_WEB_REQUEST_HEADER]: '1'
        })
      )
    ).toBe(true);
  });

  it('requires the Web header even when an API Key or rootkey header is present with a login Cookie', () => {
    expect(
      isValidWebRequest(
        request({ cookie: 'fastgpt_token=session-1', authorization: 'Bearer api-key' })
      )
    ).toBe(false);
    expect(
      isValidWebRequest(request({ cookie: 'fastgpt_token=session-1', rootkey: 'root-key' }))
    ).toBe(false);
  });

  it('does not require the Web header for API Key or rootkey requests without a login Cookie', () => {
    expect(isValidWebRequest(request({ authorization: 'Bearer api-key' }))).toBe(true);
    expect(isValidWebRequest(request({ rootkey: 'root-key' }))).toBe(true);
  });

  it('requires the Web header for all login Cookie requests regardless of route', () => {
    for (const method of ['GET', 'HEAD']) {
      expect(
        isValidWebRequest(
          request({ cookie: 'fastgpt_token=session-1' }, '/api/system/file/d/alias', method)
        )
      ).toBe(false);
      expect(
        isValidWebRequest(
          request({ cookie: 'fastgpt_token=session-1' }, '/api/system/file/download/token', method)
        )
      ).toBe(false);
      expect(
        isValidWebRequest(
          request({ cookie: 'fastgpt_token=session-1' }, '/api/common/file/read/name.txt', method)
        )
      ).toBe(false);
      expect(
        isValidWebRequest(
          request({ cookie: 'fastgpt_token=session-1' }, '/api/system/img/avatar.png', method)
        )
      ).toBe(false);
    }
  });

  it('requires the Web header for non-read methods and non-resource paths', () => {
    for (const method of ['POST', 'PUT', 'DELETE']) {
      expect(
        isValidWebRequest(
          request({ cookie: 'fastgpt_token=session-1' }, '/api/system/img/avatar.png', method)
        )
      ).toBe(false);
    }

    for (const url of [
      '/api/system/img',
      '/api/system/img-extra/avatar.png',
      '/api/common/file/read',
      '/api/common/file/read-extra/name.txt'
    ]) {
      expect(isValidWebRequest(request({ cookie: 'fastgpt_token=session-1' }, url))).toBe(false);
    }
  });

  it('rejects a Cookie request before the handler when the Web header is missing', async () => {
    const json = vi.fn();
    const res = {
      writableEnded: false,
      writableFinished: false,
      status: vi.fn(() => ({ json }))
    };

    await checkCsrf({
      req: {
        method: 'POST',
        url: '/api/core/app/update',
        headers: {
          cookie: 'fastgpt_token=session-1',
          host: 'fastgpt.example.com'
        }
      } as any,
      res: res as any
    });

    expect(res.status).toHaveBeenCalledWith(403);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ statusText: 'csrf_invalid', code: 403 })
    );
  });

  it('does not require the Web header without a login Cookie', () => {
    expect(isValidWebRequest(request({}))).toBe(true);
    expect(isValidWebRequest(request({ cookie: 'NEXT_LOCALE=en' }))).toBe(true);
  });

  it('supports standard Headers and rejects an empty Web header', () => {
    const headers = new Headers({
      cookie: 'fastgpt_token=session-1',
      [FASTGPT_WEB_REQUEST_HEADER]: '  '
    });

    expect(isValidWebRequest({ headers, method: 'GET', url: '/api/core/app/update' })).toBe(false);

    headers.set(FASTGPT_WEB_REQUEST_HEADER, '1');
    expect(isValidWebRequest({ headers, method: 'GET', url: '/api/core/app/update' })).toBe(true);
  });
});
