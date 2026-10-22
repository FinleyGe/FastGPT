#!/usr/bin/env node
import { MongoClient } from 'mongodb';
import { hashStr } from '@fastgpt/global/common/string/tools';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const DEFAULT_ROOT_PASSWORD = '123456';

/** 构造 root 密码重置更新；原生 Mongo 写入需手动遵循 Mongoose 的双层哈希格式。 */
export const createRootPasswordUpdate = (password: string) => ({
  $set: {
    password: hashStr(hashStr(password)),
    passwordUpdateTime: new Date(),
    isActivated: false
  }
});

/** 解析脚本唯一的可选参数；省略密码时使用兼容安装流程的默认值。 */
export const resolveRootPasswordArgument = (args: string[]) => {
  if (args.length > 1) throw new Error('用法：node reset-root-password.cjs [root新密码]');
  return args[0] ?? DEFAULT_ROOT_PASSWORD;
};

/** 重置 root 密码并要求账号在登录后通过账号激活流程自行设置密码。 */
export const resetRootPassword = async (password: string = DEFAULT_ROOT_PASSWORD) => {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('缺少 MONGODB_URI 环境变量');
  if (!password) throw new Error('root 密码不能为空');

  const client = new MongoClient(uri);
  try {
    await client.connect();
    const result = await client.db().collection('users').updateOne(
      { username: 'root' },
      createRootPasswordUpdate(password)
    );
    if (result.matchedCount !== 1) throw new Error('root 用户不存在');
  } finally {
    await client.close();
  }
};

/** 仅接受一个可选密码参数；省略时使用兼容安装流程的默认密码。 */
const main = async () => {
  if (process.env.RESET_ROOT_PASSWORD_SELFTEST === '1') {
    process.stdout.write('reset-root-password ready\n');
    return;
  }

  const password = resolveRootPasswordArgument(process.argv.slice(2));
  await resetRootPassword(password);
  process.stdout.write('root 密码已重置，请登录后完成账号激活\n');
};

const isEntryPoint =
  typeof __filename === 'string'
    ? __filename === process.argv[1]
    : Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  main().catch((error) => {
    process.stderr.write(`重置 root 密码失败：${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
