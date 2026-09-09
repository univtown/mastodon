import type { Meta, StoryObj } from '@storybook/react-vite';

import type { StatusVisibility } from '@/flavours/glitch/api_types/statuses';
import { statusFactoryImmutable } from '@/testing/factories';

import { BoostButton } from './boost_button';

interface StoryProps {
  visibility: StatusVisibility;
  quoteAllowed: boolean;
  alreadyBoosted: boolean;
  reblogCount: number;
  quoteCount: number;
}

const meta = {
  title: 'Components/Status/BoostButton',
  args: {
    visibility: 'public',
    quoteAllowed: true,
    alreadyBoosted: false,
    reblogCount: 0,
    quoteCount: 0,
  },
  argTypes: {
    visibility: {
      name: 'Visibility',
      control: { type: 'select' },
      options: ['public', 'unlisted', 'private', 'direct'],
    },
    reblogCount: {
      name: 'Boost Count',
    },
    quoteCount: {
      name: 'Quote Count',
      description: 'The counter displays boosts and quotes combined',
    },
    quoteAllowed: {
      name: 'Quotes allowed',
    },
    alreadyBoosted: {
      name: 'Already boosted',
    },
  },
  render: () => <BoostButton statusId='1' />,
  parameters: {
    stateFn({
      reblogCount,
      quoteCount,
      visibility,
      quoteAllowed,
      alreadyBoosted,
    }: StoryProps) {
      return {
        statuses: {
          '1': statusFactoryImmutable({
            reblogs_count: reblogCount,
            quotes_count: quoteCount,
            visibility,
            reblogged: alreadyBoosted,
            quote_approval: {
              automatic: [],
              manual: [],
              current_user: quoteAllowed ? 'automatic' : 'denied',
            },
          }),
        },
      };
    },
  },
} satisfies Meta<StoryProps>;

export default meta;

type Story = StoryObj<typeof meta>;

export const Default: Story = {};

export const BoostsAndQuotes: Story = {
  args: {
    reblogCount: 7,
    quoteCount: 5,
  },
};

export const Mine: Story = {
  parameters: {
    state: {
      meta: {
        me: '1',
      },
    },
  },
};
