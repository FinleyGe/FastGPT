/* Auth app permission */
import { MongoApp } from '../../../core/app/schema';
import { AppDetailType } from '@fastgpt/global/core/app/type.d';
import { AuthPropsType } from '../type/auth.d';
import { parseHeaderCert } from '../controller';
import { PerResourceTypeEnum } from '@fastgpt/global/support/permission/constant';
import { AppErrEnum } from '@fastgpt/global/common/error/code/app';
import { getTmbInfoByTmbId } from '../../user/team/controller';
import { getResourcePermission } from '../controller';
import { AppPermission } from '@fastgpt/global/support/permission/app/controller';
import { AuthResponseType } from '../type/auth.d';
import { PermissionValueType } from '@fastgpt/global/support/permission/type';
import { AppTypeEnum } from '@fastgpt/global/core/app/constants';

export const authAppByTmbId = async ({
  teamId,
  tmbId,
  appId,
  per
}: {
  teamId: string;
  tmbId: string;
  appId: string;
  per: PermissionValueType;
}) => {
  const { permission: tmbPer } = await getTmbInfoByTmbId({ tmbId });

  const app = await (async () => {
    // get app and per
    const [app, rp] = await Promise.all([
      MongoApp.findOne({ _id: appId, teamId }).lean(),
      getResourcePermission({
        teamId,
        tmbId,
        resourceId: appId,
        resourceType: PerResourceTypeEnum.app
      }) // this could be null
    ]);

    if (!app) {
      return Promise.reject(AppErrEnum.unExist);
    }

    const isOwner = tmbPer.isOwner || String(app.tmbId) === tmbId;
    let parentDefaultPermission = null;
    let parentRp = null;

    if (app.type !== AppTypeEnum.folder && app.inheritancePermission) {
      // app is a app rather than a folder, and app has inheritant option
      if (!app.parentId) {
        return Promise.reject(AppErrEnum.invalidAppConfig);
      }

      const parentFolder = await MongoApp.findById(app.parentId).lean();
      if (!parentFolder) {
        return Promise.reject(AppErrEnum.unExist);
      }

      parentDefaultPermission = parentFolder.defaultPermission;
      parentRp = await getResourcePermission({
        teamId,
        tmbId,
        resourceId: app.parentId,
        resourceType: PerResourceTypeEnum.app
      });
    }

    const Per = new AppPermission({
      per:
        rp?.permission ?? app.defaultPermission ?? parentRp?.permission ?? parentDefaultPermission,
      isOwner
    });

    if (!Per.checkPer(per)) {
      return Promise.reject(AppErrEnum.unAuthApp);
    }

    return {
      ...app,
      permission: Per
    };
  })();

  return { app };
};

export const authApp = async ({
  appId,
  per,
  ...props
}: AuthPropsType & {
  appId: string;
}): Promise<
  AuthResponseType & {
    app: AppDetailType;
  }
> => {
  const result = await parseHeaderCert(props);
  const { teamId, tmbId } = result;

  const { app } = await authAppByTmbId({
    teamId,
    tmbId,
    appId,
    per
  });

  return {
    ...result,
    permission: app.permission,
    app
  };
};
