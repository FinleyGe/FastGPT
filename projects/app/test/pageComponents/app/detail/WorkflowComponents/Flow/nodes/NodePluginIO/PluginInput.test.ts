import { describe, expect, it } from 'vitest';
import { FlowNodeInputTypeEnum } from '@fastgpt/global/core/workflow/node/constant';
import { getPluginInputDisplayType } from '@/pageComponents/app/detail/WorkflowComponents/Flow/nodes/NodePluginIO/PluginInput';

describe('getPluginInputDisplayType', () => {
  it('skips agentGenerated when rendering a workflow tool input icon', () => {
    expect(
      getPluginInputDisplayType([
        FlowNodeInputTypeEnum.agentGenerated,
        FlowNodeInputTypeEnum.input,
        FlowNodeInputTypeEnum.reference
      ])
    ).toBe(FlowNodeInputTypeEnum.input);
  });

  it('does not render an agentGenerated icon without an original input type', () => {
    expect(getPluginInputDisplayType([FlowNodeInputTypeEnum.agentGenerated])).toBeUndefined();
  });
});
