import type { NextApiRequest, NextApiResponse } from 'next';
import { jsonRes } from '@fastgpt/service/common/response';
import { authCert } from '@fastgpt/service/support/permission/auth/common';

type RequestBody = {
  corpId: string;
  traceId: string;
  mediaId: string;
};

const API_CONFIG = {
  baseUrl: process.env.JTTY_BASE_URL,
  appAccessKey: process.env.JTTY_APP_ACCESS_KEY,
  appId: process.env.JTTY_APP_ID,
  sysAccessKey: process.env.JTTY_SYS_ACCESS_KEY
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method !== 'POST') {
      return jsonRes(res, {
        code: 405,
        error: 'Method not allowed'
      });
    }

    // 身份验证 - 确保用户有权限访问
    await authCert({
      req,
      authToken: true
    });

    const { corpId, traceId, mediaId }: RequestBody = req.body;

    // 参数验证
    if (!corpId || !traceId || !mediaId) {
      return jsonRes(res, {
        code: 400,
        error: 'Missing required parameters: corpId, traceId, mediaId'
      });
    }

    // 检查API配置
    if (!API_CONFIG.sysAccessKey || !API_CONFIG.appId || !API_CONFIG.appAccessKey) {
      return jsonRes(res, {
        code: 500,
        error: 'Server configuration error: missing API credentials'
      });
    }

    // 构建请求参数
    const queryParams = new URLSearchParams({
      sysAccessKey: API_CONFIG.sysAccessKey,
      corpId,
      appId: API_CONFIG.appId,
      appAccessKey: API_CONFIG.appAccessKey,
      mediaId,
      traceId
    });

    const apiUrl = `${API_CONFIG.baseUrl}/v2/open/api/onpremise/memo/getOneTimeToken?${queryParams}`;

    console.log('Memo API request URL:', apiUrl);

    // 发送请求到外部API
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'FastGPT/1.0'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`External API error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    console.log('Memo API response:', result);

    // 返回结果
    return jsonRes(res, {
      data: result
    });
  } catch (error) {
    console.error('Memo API proxy error:', error);

    return jsonRes(res, {
      code: 500,
      error: error instanceof Error ? error.message : 'Internal server error'
    });
  }
}
