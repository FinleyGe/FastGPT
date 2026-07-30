import { describe, expect, it } from 'vitest';
import { FlowNodeInputTypeEnum } from '@fastgpt/global/core/workflow/node/constant';
import {
  getToolVersionDisplayLabel,
  inheritToolInputConfig,
  preserveConfiguredToolIdentity
} from '@/pageComponents/app/detail/Edit/FormComponent/ToolSelector/utils';
import type { FlowNodeTemplateType } from '@fastgpt/global/core/workflow/type/node';

const createTool = (inputs: FlowNodeTemplateType['inputs']) =>
  ({
    id: 'tool',
    name: 'Tool',
    flowNodeType: 'tool',
    templateType: 'test',
    inputs,
    outputs: []
  }) as unknown as FlowNodeTemplateType;

describe('ToolSelector utils', () => {
  it('should restore the selected version label from the loaded version list', () => {
    const tool = {
      ...createTool([]),
      version: 'fixed-version',
      versionLabel: undefined
    };

    expect(
      getToolVersionDisplayLabel({
        tool,
        versionList: [
          {
            version: 'fixed-version',
            versionDescription: 'Resume assistant'
          }
        ],
        latestVersionLabel: 'Keep latest'
      })
    ).toBe('Resume assistant');
  });

  it('should not expose the version ID when the version label is unavailable', () => {
    const tool = {
      ...createTool([]),
      pluginId: 'systemTool-workflow-tool',
      flowNodeType: 'pluginModule',
      version: 'internal-version-id',
      versionLabel: undefined
    };

    expect(
      getToolVersionDisplayLabel({
        tool,
        versionList: [],
        latestVersionLabel: 'Keep latest'
      })
    ).toBe('');
  });

  it('should display the version number for a regular system tool', () => {
    const tool = {
      ...createTool([]),
      pluginId: 'systemTool-test-tool',
      flowNodeType: 'tool',
      version: '1.0.0',
      versionLabel: undefined
    };

    expect(
      getToolVersionDisplayLabel({
        tool,
        versionList: [],
        latestVersionLabel: 'Keep latest'
      })
    ).toBe('1.0.0');
  });

  it('should preserve the selected tool identity when switching a personal tool version', () => {
    const appId = '507f1f77bcf86cd799439011';
    const prevTool = {
      ...createTool([]),
      id: `personal-${appId}`,
      pluginId: `personal-${appId}`,
      version: '',
      versionLabel: 'Latest'
    };
    const nextTool = {
      ...createTool([]),
      id: 'new-preview-node-id',
      pluginId: appId,
      version: 'fixed-version',
      versionLabel: 'Resume assistant'
    };

    const mergedTool = preserveConfiguredToolIdentity({
      tool: nextTool,
      sourceTool: prevTool
    });
    const selectedTools = [prevTool].map((tool) =>
      tool.pluginId === mergedTool.pluginId ? mergedTool : tool
    );

    expect(selectedTools[0]).toMatchObject({
      id: `personal-${appId}`,
      pluginId: `personal-${appId}`,
      version: 'fixed-version',
      versionLabel: 'Resume assistant'
    });
  });

  describe('inheritToolInputConfig', () => {
    it('should inherit value and explicit input selection while keeping the current tool schema', () => {
      const tool = createTool([
        {
          key: 'query',
          label: 'Query',
          value: 'template value',
          renderTypeList: [FlowNodeInputTypeEnum.agentGenerated, FlowNodeInputTypeEnum.input],
          selectedTypeIndex: 0,
          toolDescription: 'new description',
          isToolParam: true,
          required: true
        },
        {
          key: 'limit',
          label: 'Limit',
          value: 10,
          renderTypeList: [FlowNodeInputTypeEnum.numberInput],
          required: true
        }
      ]);
      const sourceTool = createTool([
        {
          key: 'query',
          label: 'Old Query',
          value: 'manual value',
          valueDesc: 'manual desc',
          renderTypeList: [FlowNodeInputTypeEnum.input, FlowNodeInputTypeEnum.agentGenerated],
          selectedType: FlowNodeInputTypeEnum.input,
          selectedTypeIndex: 0,
          toolDescription: 'source description',
          isToolParam: false
        }
      ]);

      const result = inheritToolInputConfig({ tool, sourceTool });

      expect(result.inputs[0]).toMatchObject({
        key: 'query',
        label: 'Query',
        value: 'manual value',
        valueDesc: 'manual desc',
        renderTypeList: [FlowNodeInputTypeEnum.agentGenerated, FlowNodeInputTypeEnum.input],
        selectedType: FlowNodeInputTypeEnum.input,
        selectedTypeIndex: 1,
        toolDescription: 'new description',
        required: true
      });
      expect(result.inputs[0]).not.toHaveProperty('isToolParam');
      expect(result.inputs[1]).toMatchObject({
        key: 'limit',
        label: 'Limit',
        value: 10,
        required: true,
        renderTypeList: [FlowNodeInputTypeEnum.agentGenerated, FlowNodeInputTypeEnum.numberInput]
      });
      expect(result.inputs[1]).not.toHaveProperty('isToolParam');
      expect(result).not.toBe(tool);
    });

    it('should apply the default mode and omit isToolParam for a new tool', () => {
      const tool = createTool([
        {
          key: 'query',
          label: 'Query',
          renderTypeList: [FlowNodeInputTypeEnum.input, FlowNodeInputTypeEnum.reference],
          selectedType: FlowNodeInputTypeEnum.input,
          selectedTypeIndex: 0,
          isToolParam: true
        }
      ]);

      const result = inheritToolInputConfig({ tool });

      expect(result.inputs[0]).toMatchObject({
        selectedType: FlowNodeInputTypeEnum.agentGenerated
      });
      expect(result.inputs[0]).not.toHaveProperty('isToolParam');
    });

    it('should use isToolParam instead of toolDescription for a new system tool', () => {
      const tool = {
        ...createTool([
          {
            key: 'query',
            label: 'Query',
            renderTypeList: [FlowNodeInputTypeEnum.input, FlowNodeInputTypeEnum.reference],
            selectedType: FlowNodeInputTypeEnum.input,
            selectedTypeIndex: 0,
            isToolParam: false,
            toolDescription: 'Search query'
          }
        ]),
        pluginId: 'systemTool-search'
      };

      const result = inheritToolInputConfig({ tool });

      expect(result.inputs[0]).toMatchObject({
        selectedType: FlowNodeInputTypeEnum.input,
        renderTypeList: [
          FlowNodeInputTypeEnum.agentGenerated,
          FlowNodeInputTypeEnum.input,
          FlowNodeInputTypeEnum.reference
        ]
      });
    });

    it('should restore a new legacy system tool input while keeping saved selections', () => {
      const tool = {
        ...createTool([
          {
            key: 'query',
            label: 'Query',
            renderTypeList: [FlowNodeInputTypeEnum.input, FlowNodeInputTypeEnum.reference],
            toolDescription: 'Search query'
          },
          {
            key: 'count',
            label: 'Count',
            valueType: 'number',
            renderTypeList: [FlowNodeInputTypeEnum.numberInput],
            isToolParam: true,
            toolDescription: 'Result count'
          }
        ]),
        pluginId: 'systemTool-search'
      };
      const sourceTool = {
        ...createTool([
          {
            key: 'query',
            label: 'Query',
            renderTypeList: [
              FlowNodeInputTypeEnum.agentGenerated,
              FlowNodeInputTypeEnum.input,
              FlowNodeInputTypeEnum.reference
            ],
            selectedType: FlowNodeInputTypeEnum.input,
            selectedTypeIndex: 1,
            toolDescription: 'Search query'
          }
        ]),
        pluginId: 'systemTool-search'
      };

      const result = inheritToolInputConfig({ tool, sourceTool });

      expect(result.inputs[0]).toMatchObject({
        selectedType: FlowNodeInputTypeEnum.input,
        selectedTypeIndex: 1
      });
      expect(result.inputs[1]).toMatchObject({
        selectedType: FlowNodeInputTypeEnum.agentGenerated,
        renderTypeList: [FlowNodeInputTypeEnum.agentGenerated, FlowNodeInputTypeEnum.numberInput]
      });
    });

    it('should not apply toolDescription fallback to MCP tools', () => {
      const tool = {
        ...createTool([
          {
            key: 'query',
            label: 'Query',
            renderTypeList: [FlowNodeInputTypeEnum.input, FlowNodeInputTypeEnum.reference],
            selectedTypeIndex: 0,
            toolDescription: 'Search query'
          }
        ]),
        pluginId: 'mcp-app/search'
      };

      const result = inheritToolInputConfig({ tool, sourceTool: tool });

      expect(result.inputs[0]).toMatchObject({
        selectedType: FlowNodeInputTypeEnum.input,
        selectedTypeIndex: 1,
        renderTypeList: [
          FlowNodeInputTypeEnum.agentGenerated,
          FlowNodeInputTypeEnum.input,
          FlowNodeInputTypeEnum.reference
        ]
      });
    });
  });
});
