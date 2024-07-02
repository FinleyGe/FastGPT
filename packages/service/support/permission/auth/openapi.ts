import { AuthResponseType } from '@fastgpt/global/support/permission/type';
import { AuthModeType } from '../type';
import { OpenApiSchema } from '@fastgpt/global/support/openapi/type';
import { parseHeaderCert } from '../controller';
import { getTmbInfoByTmbId } from '../../user/team/controller';
import { MongoOpenApi } from '../../openapi/schema';
import { OpenApiErrEnum } from '@fastgpt/global/common/error/code/openapi';
import {
  OwnerPermissionVal,
  WritePermissionVal
} from '@fastgpt/global/support/permission/constant';

export async function authOpenApiKeyCrud({
  id,
  per = OwnerPermissionVal,
  ...props
}: AuthModeType & {
  id: string;
}): Promise<
  AuthResponseType & {
    openapi: OpenApiSchema;
  }
> {
  const result = await parseHeaderCert(props);
  const { tmbId, teamId } = result;

  const { permission } = await getTmbInfoByTmbId({ tmbId });

  const { openapi, isOwner, canWrite } = await (async () => {
    const openapi = await MongoOpenApi.findOne({ _id: id, teamId });

    if (!openapi) {
      throw new Error(OpenApiErrEnum.unExist);
    }

    const isOwner = String(openapi.tmbId) === tmbId || permission.isOwner;
    const canWrite = isOwner || (String(openapi.tmbId) === tmbId && permission.hasWritePer);

    if (!permission.checkPer(per)) {
      return Promise.reject(OpenApiErrEnum.unAuth);
    }

    return {
      openapi,
      isOwner,
      canWrite
    };
  })();

  return {
    ...result,
    openapi,
    isOwner,
    canWrite
  };
}
