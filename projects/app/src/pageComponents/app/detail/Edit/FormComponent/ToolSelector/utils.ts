import {
  canInputBeAgentGenerated,
  getSavedToolInputSelectedType,
  initToolInputTypeByDefaultMode,
  isAgentGeneratedToolInput,
  stripToolInputDefaultMode
} from '@fastgpt/global/core/app/formEdit/utils';
import type { FlowNodeInputItemType } from '@fastgpt/global/core/workflow/type/io';
import type { FlowNodeTemplateType } from '@fastgpt/global/core/workflow/type/node';
import type { SelectedToolItemType } from '@fastgpt/global/core/app/formEdit/type';
import type { SystemToolVersionType } from '@fastgpt/global/core/app/tool/systemTool/type/base';
import { FlowNodeTypeEnum } from '@fastgpt/global/core/workflow/node/constant';
import { isSystemOrCommercialToolId } from '@fastgpt/global/core/app/tool/utils';

const canDisplayToolVersionValue = (tool: SelectedToolItemType) =>
  isSystemOrCommercialToolId(tool.pluginId) && tool.flowNodeType !== FlowNodeTypeEnum.pluginModule;

/** 获取工具版本选择器的展示文案，避免将工作流工具的内部版本 ID 暴露给用户。 */
export const getToolVersionDisplayLabel = ({
  tool,
  versionList,
  latestVersionLabel
}: {
  tool: SelectedToolItemType;
  versionList: SystemToolVersionType[];
  latestVersionLabel: string;
}) => {
  if (!tool.version) return latestVersionLabel;
  if (tool.versionLabel) return tool.versionLabel;

  const matchedVersion = versionList.find((item) => item.version === tool.version);
  if (matchedVersion?.versionDescription) return matchedVersion.versionDescription;

  return canDisplayToolVersionValue(tool) ? tool.version : '';
};

/** 判断固定版本工具是否需要加载版本列表来补齐展示名称。 */
export const shouldLoadToolVersions = (tool: SelectedToolItemType) =>
  Boolean(tool.version && !tool.versionLabel && !canDisplayToolVersionValue(tool));

/** 使用原工具身份承接 preview 返回的新版本定义，确保父级能替换当前工具。 */
export const preserveConfiguredToolIdentity = <T extends FlowNodeTemplateType>({
  tool,
  sourceTool
}: {
  tool: T;
  sourceTool: Pick<SelectedToolItemType, 'id' | 'pluginId'>;
}): T => ({
  ...tool,
  id: sourceTool.id,
  pluginId: sourceTool.pluginId
});

export const countAgentGeneratedToolInputs = (tool: Pick<FlowNodeTemplateType, 'inputs'>) =>
  tool.inputs.filter((input) => isAgentGeneratedToolInput(input) && canInputBeAgentGenerated(input))
    .length;

export const inheritToolInputConfig = <T extends Pick<FlowNodeTemplateType, 'inputs'>>({
  tool,
  sourceTool
}: {
  tool: T;
  sourceTool?: Pick<FlowNodeTemplateType, 'inputs'>;
}): T => {
  const sourceInputMap = new Map(sourceTool?.inputs.map((input) => [input.key, input]));

  return {
    ...tool,
    inputs: tool.inputs.map((input) => {
      const sourceInput = sourceInputMap.get(input.key);
      const selectedType = getSavedToolInputSelectedType({
        savedInput: sourceInput,
        defaultInput: input,
        allowUserChatInputAgentGenerated: true
      });
      const normalizedInput = initToolInputTypeByDefaultMode(input, {
        forceDefaultMode: selectedType === undefined,
        allowUserChatInputAgentGenerated: true
      });
      if (!sourceInput) return stripToolInputDefaultMode(normalizedInput);

      const renderTypeList =
        selectedType && !normalizedInput.renderTypeList.includes(selectedType)
          ? [selectedType, ...normalizedInput.renderTypeList]
          : normalizedInput.renderTypeList;
      const selectedTypeIndex =
        selectedType !== undefined
          ? renderTypeList.findIndex((item) => item === selectedType)
          : normalizedInput.selectedTypeIndex;

      return stripToolInputDefaultMode({
        ...normalizedInput,
        value: sourceInput.value,
        valueDesc: sourceInput.valueDesc,
        renderTypeList,
        selectedType: selectedType ?? normalizedInput.selectedType,
        selectedTypeIndex:
          selectedTypeIndex !== undefined && selectedTypeIndex >= 0 ? selectedTypeIndex : undefined,
        toolDescription: input.toolDescription ?? sourceInput.toolDescription
      } satisfies FlowNodeInputItemType);
    })
  } as T;
};
