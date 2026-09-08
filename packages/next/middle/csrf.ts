import type { NextApiRequest, NextApiResponse } from 'next';

export const FASTGPT_WEB_REQUEST_HEADER = 'fastgpt-web-request';
export const FASTGPT_WEB_REQUEST_VALUE = '1';

type RequestHeaders = Headers | Record<string, string | string[] | undefined>;
type WebRequest = {
  headers: RequestHeaders;
  method?: string;
  url?: string;
};

type CsrfCheckOptions = {
  req: NextApiRequest;
  res: NextApiResponse;
  allowedOrigins?: string[];
};

const getHeader = (headers: RequestHeaders, name: string) => {
  if ('get' in headers && typeof headers.get === 'function') {
    return headers.get(name) ?? undefined;
  }

  const recordHeaders = headers as Record<string, string | string[] | undefined>;
  const value = recordHeaders[name] ?? recordHeaders[name.toLowerCase()];
  return Array.isArray(value) ? value.join(',') : value;
};

/** 解析跨域白名单；未配置时返回 undefined，以保留默认允许所有跨域的兼容行为。 */
export const parseAllowedOrigins = (value?: string) => {
  if (!value?.trim()) return undefined;

  return value
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
};

/**
 * 校验请求来源。未配置白名单时允许任意来源；配置后允许同源请求和白名单中的跨域请求。
 * Origin 缺失表示非 CORS 请求，交由 Cookie/Header 等其他防线继续校验。
 */
export const isAllowedOrigin = (
  origin: string | null | undefined,
  sameOrigin: string,
  allowedOrigins?: string[]
) => {
  if (!origin || !allowedOrigins || origin === sameOrigin) return true;
  return allowedOrigins.includes(origin);
};

/** 将 Referer 转换为 Origin 后复用同一份来源白名单校验。 */
export const isAllowedReferer = (
  referer: string | null | undefined,
  sameOrigin: string,
  allowedOrigins?: string[]
) => {
  if (!referer) return false;

  try {
    return isAllowedOrigin(new URL(referer).origin, sameOrigin, allowedOrigins);
  } catch {
    return false;
  }
};

const hasCookie = (cookie: string | undefined, name: string) =>
  cookie?.split(';').some((item) => item.trim().startsWith(`${name}=`)) ?? false;

/** 判断登录 Cookie 请求是否需要 Web 请求标记。 */
export const shouldValidateWebRequest = (req: WebRequest) =>
  hasCookie(getHeader(req.headers, 'cookie'), 'fastgpt_token');

/** 校验登录 Cookie 请求是否带有由 FastGPT Web 客户端添加的标记。 */
export const isValidWebRequest = (req: WebRequest) => {
  if (!shouldValidateWebRequest(req)) return true;
  const value = getHeader(req.headers, FASTGPT_WEB_REQUEST_HEADER);
  return typeof value === 'string' && value.trim().length > 0;
};

const getRequestOrigin = (req: NextApiRequest) => {
  const protocol = getHeader(req.headers, 'x-forwarded-proto')?.split(',')[0] || 'http';
  const host = getHeader(req.headers, 'host');
  return host ? `${protocol}://${host}` : '';
};

/**
 * 在 API handler 执行前校验来源和登录 Cookie 请求标记。
 * CSRF 配置由 NextAPI 决定；该函数只负责校验失败时写入 403 响应。
 */
export async function checkCsrf({ req, res, allowedOrigins }: CsrfCheckOptions) {
  if (res.writableEnded || res.writableFinished) return;

  const origin = getHeader(req.headers, 'origin');
  const sameOrigin = getRequestOrigin(req);
  const isUnsafeMethod = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method ?? '');
  const isCookieRequest = shouldValidateWebRequest({
    headers: req.headers,
    method: req.method,
    url: req.url
  });
  const isRefererAllowed = isAllowedReferer(
    getHeader(req.headers, 'referer'),
    sameOrigin,
    allowedOrigins
  );
  const isOriginAllowed = isAllowedOrigin(origin, sameOrigin, allowedOrigins);
  const isMissingOriginAllowed =
    !!origin || !allowedOrigins || !isUnsafeMethod || !isCookieRequest || isRefererAllowed;

  if (!isOriginAllowed || !isMissingOriginAllowed) {
    res.status(403).json({
      code: 403,
      statusText: 'origin_invalid',
      message: 'Request origin is not allowed',
      data: null
    });
    return;
  }

  if (
    req.method === 'OPTIONS' ||
    isValidWebRequest({ headers: req.headers, method: req.method, url: req.url })
  ) {
    return;
  }

  res.status(403).json({
    code: 403,
    statusText: 'csrf_invalid',
    message: 'Missing fastgpt-web-request header',
    data: null
  });
}
