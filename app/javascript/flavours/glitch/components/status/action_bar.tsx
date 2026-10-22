import { useCallback } from 'react';

import { FormattedMessage, useIntl } from 'react-intl';

import classNames from 'classnames';

import { DotsThreeIcon, ShareFatIcon } from '@phosphor-icons/react';

import { statusInteraction } from '@/flavours/glitch/actions/interactions';
import { fetchStatus } from '@/flavours/glitch/actions/statuses';
import { useCurrentAccountId } from '@/flavours/glitch/hooks/useAccountId';
import { useAccountStatus } from '@/flavours/glitch/hooks/useStatus';
import {
  quickBoosting,
  showInteractionCounts,
} from '@/flavours/glitch/initial_state';
import type { AccountStatusShape } from '@/flavours/glitch/models/status';
import { useAppDispatch, useAppSelector } from '@/flavours/glitch/store';

import {
  Button,
  IconButton,
  ToggleButton,
  ToggleIconButton,
} from '../button/redesign';
import {
  Menu,
  MenuItem,
  MenuList,
  MenuTrigger,
  LegacyDropdownMenuItems,
} from '../menu';
import { ShortNumber } from '../short_number';

import {
  useStatusContext,
  useStatusIcons,
  useStatusMenuActions,
} from './hooks';
import { RemoveQuoteHint } from './legacy/action_bar/remove_quote_hint';
import classes from './styles.module.scss';

interface StatusActionBarProps {
  statusId: string;
  withDismiss?: boolean;
  withCounters?: boolean;
  /** Only show methods to respond (reply, boost, like) and not sharing, bookmarking, and the overflow menu. */
  onlyResponses?: boolean;
}

export const StatusActionBar: React.FC<StatusActionBarProps> = ({
  statusId,
  withDismiss,
  withCounters,
  onlyResponses,
}) => {
  const status = useAccountStatus(statusId);
  const quotedAccountId = useAppSelector(
    (state) =>
      state.statuses.getIn([status?.quote?.quoted_status, 'account']) ?? null,
  );
  const currentAccountId = useCurrentAccountId();
  const { contextType } = useStatusContext();
  const statusUrl = status?.url ?? status?.uri;

  // Actions
  const dispatch = useAppDispatch();
  const handleShareClick = useCallback(() => {
    if (!statusUrl) {
      return;
    }

    // We need to make this partial as by default share always is set, despite not being supported in FF.
    const nav = navigator as Partial<Pick<Navigator, 'share'>> &
      Pick<Navigator, 'clipboard'>;
    if (nav.share) {
      void nav.share({
        url: statusUrl,
      });
    } else {
      dispatch(statusInteraction({ statusId, intent: 'copy', contextType }));
    }
  }, [contextType, dispatch, statusId, statusUrl]);

  const { reply, like, bookmark, boost } = useStatusIcons(statusId);
  const intl = useIntl();
  const showReplyCount = useAppSelector(
    (state) =>
      state.local_settings.get('show_status_reply_count', true) as boolean,
  );

  if (!status) {
    return null;
  }

  const showCounters = showInteractionCounts && withCounters !== false;
  const showReplies = showCounters && showReplyCount;
  const propagationCount = status.reblogs_count + status.quotes_count;
  const countTitle = (title: string, count: number) =>
    showCounters ? `${title} · ${intl.formatNumber(count)}` : title;
  const isPublic =
    status.visibility === 'public' || status.visibility === 'unlisted';

  const isQuotingMe = quotedAccountId === currentAccountId;
  const shouldShowQuoteRemovalHint =
    isQuotingMe && contextType === 'notifications';

  const responseButtons = (
    <>
      <Button
        size='sm'
        clipPadding
        variant='ghost'
        leadingIcon={reply.icon}
        onClick={reply.action}
        tooltip={{
          type: 'label',
          text: showReplies
            ? countTitle(reply.title, reply.counter ?? 0)
            : reply.title,
        }}
      >
        {showReplies && reply.counter !== undefined && (
          <ShortNumber value={reply.counter} />
        )}
      </Button>

      <StatusReblogButton
        statusId={statusId}
        title={countTitle(boost.title, propagationCount)}
      >
        {showCounters && propagationCount > 0 && (
          <ShortNumber value={propagationCount} />
        )}
      </StatusReblogButton>

      <ToggleButton
        size='sm'
        variant='ghost'
        active={like.active}
        tooltip={{
          type: 'label',
          text: countTitle(like.title, like.counter ?? 0),
        }}
        leadingIcon={like.icon}
        onClick={like.action}
        className={classNames(!onlyResponses && classes.actionsButtonGap)}
      >
        {showCounters && like.counter !== undefined && (
          <ShortNumber value={like.counter} />
        )}
      </ToggleButton>
    </>
  );

  if (onlyResponses) {
    return <div className={classes.actions}>{responseButtons}</div>;
  }

  return (
    <div className={classes.actions}>
      {responseButtons}

      {isPublic && (
        <IconButton
          size='sm'
          variant='ghost'
          icon={ShareFatIcon}
          onClick={handleShareClick}
        >
          <FormattedMessage id='status.share' defaultMessage='Share' />
        </IconButton>
      )}

      <ToggleIconButton
        size='sm'
        variant='ghost'
        active={bookmark.active}
        icon={bookmark.icon}
        onClick={bookmark.action}
      >
        {bookmark.title}
      </ToggleIconButton>

      <RemoveQuoteHint
        className='status__action-bar__button-wrapper'
        canShowHint={shouldShowQuoteRemovalHint}
      >
        {(dismissQuoteHint) => (
          <StatusActionMenu
            dismissQuoteHint={dismissQuoteHint}
            status={status}
            withDismiss={withDismiss}
          />
        )}
      </RemoveQuoteHint>
    </div>
  );
};

const StatusReblogButton: React.FC<{
  statusId: string;
  title: string;
  children: React.ReactNode;
}> = ({ statusId, title, children }) => {
  const { boost, quote } = useStatusIcons(statusId);

  if (quickBoosting) {
    return (
      <ToggleButton
        size='sm'
        variant='ghost'
        active={boost.active}
        tooltip={{
          type: 'label',
          text: title,
        }}
        leadingIcon={boost.icon}
        disabled={boost.disabled}
        onClick={boost.action}
      >
        {children}
      </ToggleButton>
    );
  }

  return (
    <Menu>
      <MenuTrigger
        as={ToggleButton}
        size='sm'
        variant='ghost'
        active={boost.active}
        tooltip={{
          type: 'label',
          text: title,
        }}
        leadingIcon={boost.icon}
      >
        {children}
      </MenuTrigger>

      <MenuList placement='bottom' maxWidth={180}>
        <MenuItem
          onClick={boost.action}
          icon={boost.icon}
          disabled={boost.disabled}
          description={boost.meta}
        >
          {boost.title}
        </MenuItem>
        <MenuItem
          onClick={quote.action}
          icon={quote.icon}
          disabled={quote.disabled}
          description={quote.meta}
        >
          {quote.title}
        </MenuItem>
      </MenuList>
    </Menu>
  );
};

const StatusActionMenu: React.FC<{
  dismissQuoteHint: () => void;
  status: AccountStatusShape;
  withDismiss?: boolean;
}> = ({ status, dismissQuoteHint, withDismiss }) => {
  const { contextType } = useStatusContext();
  const dispatch = useAppDispatch();

  const menu = useStatusMenuActions({ status, contextType, withDismiss });

  const onOpen = useCallback(() => {
    // Replicates needsStatusRefresh of the Dropdown component.
    if (quickBoosting && !status.quote_approval) {
      dispatch(
        fetchStatus(status.id, { forceFetch: true, alsoFetchContext: false }),
      );
    }

    dismissQuoteHint();
  }, [dismissQuoteHint, dispatch, status.id, status.quote_approval]);

  return (
    <Menu onOpen={onOpen}>
      <MenuTrigger
        as={IconButton}
        size='sm'
        variant='ghost'
        icon={DotsThreeIcon}
      >
        <FormattedMessage id='status.more' defaultMessage='More' />
      </MenuTrigger>

      <MenuList placement='top-end'>
        <LegacyDropdownMenuItems items={menu} />
      </MenuList>
    </Menu>
  );
};
