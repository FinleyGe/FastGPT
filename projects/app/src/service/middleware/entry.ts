import { checkCsrf, parseAllowedOrigins } from '@fastgpt/next/middle/csrf';
import { withNextCors } from '@fastgpt/next/middle/cors';
import type { NextApiRequest, NextApiResponse } from '@fastgpt/next/type';
import { createApiEntry, type ApiHandler } from '@fastgpt/service/common/http/entry';
import { serviceEnv } from '@fastgpt/service/env';

type NextAPIOptions = {
  csrf?: boolean;
};

export const NextAPI = (
  ...args: (ApiHandler<any, NextApiRequest, NextApiResponse> | NextAPIOptions)[]
) => {
  const lastArg = args[args.length - 1];
  const options = typeof lastArg === 'object' ? lastArg : {};
  const handlers = (typeof lastArg === 'object' ? args.slice(0, -1) : args) as ApiHandler<
    any,
    NextApiRequest,
    NextApiResponse
  >[];
  const allowedOrigins = parseAllowedOrigins(serviceEnv.ALLOWED_ORIGINS);

  /** 按接口声明顺序执行 CORS 和 CSRF；CSRF 短路时不再继续后置校验。 */
  const beforeRequest = async (req: NextApiRequest, res: NextApiResponse) => {
    await withNextCors({ req, res, allowedOrigins });
    if (res.writableEnded || res.writableFinished) return;

    if (options.csrf !== false) {
      await checkCsrf({ req, res, allowedOrigins });
    }
  };

  return createApiEntry<NextApiRequest, NextApiResponse>({
    beforeCallback: [beforeRequest]
  })(...handlers);
};
