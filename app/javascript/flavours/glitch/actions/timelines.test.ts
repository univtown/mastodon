import { Map as ImmutableMap } from 'immutable';

import type { ApiStatusJSON } from '../api_types/statuses';
import type { AppDispatch, RootState } from '../store/store';

import { updateTimeline } from './timelines';
import {
  insertStatusIntoAccountTimelines,
  parseTimelineKey,
  timelineKey,
} from './timelines_typed';

vi.mock('./timelines', () => ({
  updateTimeline: vi.fn(() => ({ type: 'test/updateTimeline' })),
}));

describe('insertStatusIntoAccountTimelines', () => {
  test.each(['author', 'proxy'])(
    'inserts a post into its %s account timeline',
    (authorId) => {
      const status = {
        account: { id: authorId },
        tags: [],
      } as unknown as ApiStatusJSON;
      const authorKey = timelineKey({ type: 'account', userId: authorId });
      const state = {
        meta: ImmutableMap({ me: 'author' }),
        timelines: ImmutableMap({
          [timelineKey({ type: 'account', userId: 'author' })]: ImmutableMap(),
          [timelineKey({ type: 'account', userId: 'proxy' })]: ImmutableMap(),
          [timelineKey({ type: 'account', userId: authorId, pinned: true })]:
            ImmutableMap(),
          [timelineKey({ type: 'account', userId: authorId, tagged: 'other' })]:
            ImmutableMap(),
        }),
      } as unknown as RootState;

      vi.mocked(updateTimeline).mockClear();
      insertStatusIntoAccountTimelines(status)(
        vi.fn() as AppDispatch,
        () => state,
      );

      expect(updateTimeline).toHaveBeenCalledExactlyOnceWith(authorKey, status);
    },
  );
});

describe('timelineKey', () => {
  test('returns expected key for account timeline with filters', () => {
    const key = timelineKey({
      type: 'account',
      userId: '123',
      replies: true,
      boosts: false,
      media: true,
    });
    expect(key).toBe('account:123:0110');
  });

  test('returns expected key for account timeline with tag', () => {
    const key = timelineKey({
      type: 'account',
      userId: '456',
      tagged: 'nature',
      replies: true,
    });
    expect(key).toBe('account:456:0100:nature');
  });

  test('returns expected key for account timeline with pins', () => {
    const key = timelineKey({
      type: 'account',
      userId: '789',
      pinned: true,
    });
    expect(key).toBe('account:789:0001');
  });
});

describe('parseTimelineKey', () => {
  test('parses account timeline key with filters correctly', () => {
    const params = parseTimelineKey('account:123:1010');
    expect(params).toEqual({
      type: 'account',
      userId: '123',
      boosts: true,
      replies: false,
      media: true,
      pinned: false,
    });
  });

  test('parses account timeline key with tag correctly', () => {
    const params = parseTimelineKey('account:456:0100:nature');
    expect(params).toEqual({
      type: 'account',
      userId: '456',
      replies: true,
      boosts: false,
      media: false,
      pinned: false,
      tagged: 'nature',
    });
  });

  test('parses legacy account timeline key with pinned correctly', () => {
    const params = parseTimelineKey('account:789:pinned:nature');
    expect(params).toEqual({
      type: 'account',
      userId: '789',
      replies: false,
      boosts: false,
      media: false,
      pinned: true,
      tagged: 'nature',
    });
  });

  test('parses legacy account timeline key with media correctly', () => {
    const params = parseTimelineKey('account:789:media');
    expect(params).toEqual({
      type: 'account',
      userId: '789',
      replies: false,
      boosts: false,
      media: true,
      pinned: false,
    });
  });
});
