# frozen_string_literal: true

class Api::V1::StatusesController < Api::BaseController
  include Authorization
  include AsyncRefreshesConcern
  include Api::InteractionPoliciesConcern
  include Redisable

  before_action -> { authorize_if_got_token! :read, :'read:statuses' }, except: [:create, :update, :destroy]
  before_action -> { doorkeeper_authorize! :write, :'write:statuses' }, only:   [:create, :update, :destroy]
  before_action :require_user!, except:      [:index, :show, :context]
  before_action :set_statuses, only:         [:index]
  before_action :set_status, only:           [:show, :context]
  before_action :set_thread, only:           [:create]
  before_action :set_quoted_status, only:    [:create]
  before_action :check_statuses_limit, only: [:index]

  override_rate_limit_headers :create, family: :statuses
  override_rate_limit_headers :update, family: :statuses

  # This API was originally unlimited, pagination cannot be introduced without
  # breaking backwards-compatibility. Arbitrarily high number to cover most
  # conversations as quasi-unlimited, it would be too much work to render more
  # than this anyway
  CONTEXT_LIMIT = 4_096

  # This remains expensive and we don't want to show everything to logged-out users
  ANCESTORS_LIMIT         = 40
  DESCENDANTS_LIMIT       = 60
  DESCENDANTS_DEPTH_LIMIT = 20

  def index
    @statuses = preload_collection(@statuses, Status)
    render json: @statuses, each_serializer: REST::StatusSerializer
  end

  def show
    cache_if_unauthenticated!
    @status = preload_collection([@status], Status).first
    render json: @status, serializer: REST::StatusSerializer, discord_hack: request.user_agent && request.user_agent.include?('Discordbot/2.0')
  end

  def context
    cache_if_unauthenticated!

    ancestors_limit         = CONTEXT_LIMIT
    descendants_limit       = CONTEXT_LIMIT
    descendants_depth_limit = nil

    if current_account.nil?
      ancestors_limit         = ANCESTORS_LIMIT
      descendants_limit       = DESCENDANTS_LIMIT
      descendants_depth_limit = DESCENDANTS_DEPTH_LIMIT
    end

    ancestors_results   = @status.in_reply_to_id.nil? ? [] : @status.ancestors(ancestors_limit, current_account)
    descendants_results = @status.descendants(descendants_limit, current_account, descendants_depth_limit)
    loaded_ancestors    = preload_collection(ancestors_results, Status)
    loaded_descendants  = preload_collection(descendants_results, Status)

    @context = Context.new(ancestors: loaded_ancestors, descendants: loaded_descendants)
    statuses = [@status] + @context.ancestors + @context.descendants

    refresh_key = "context:#{@status.id}:refresh"
    async_refresh = AsyncRefresh.new(refresh_key)

    if async_refresh.running?
      add_async_refresh_header(async_refresh)
    elsif !current_account.nil? && @status.should_fetch_replies?
      add_async_refresh_header(AsyncRefresh.create(refresh_key, count_results: true))

      WorkerBatch.new.within do |batch|
        batch.connect(refresh_key, threshold: 1.0)
        ActivityPub::FetchAllRepliesWorker.perform_async(@status.id, { 'batch_id' => batch.id })
      end
    end

    render json: @context, serializer: REST::ContextSerializer, relationships: StatusRelationshipsPresenter.new(statuses, current_user&.account_id)
  end

  def create
    original_text = status_params[:status]
    transferred_media = []

    if should_post_anonymously?(original_text)
      anon_config = Rails.configuration.x.anon
      proxy_account = Account.find_by(username: anon_config.account_username)

      if proxy_account
        anonymous_name = generate_anonymous_name(current_user.account)

        if anonymous_name
          cleaned_text = Status.new.clean_anonymous_tag(original_text)

          if cleaned_text.blank?
            Rails.logger.warn('Anonymous post content is empty after cleaning, falling back to normal post')
            processed_text = original_text
            sender_account = current_user.account
            application_to_use = doorkeeper_token.application
          else
            processed_text = "[#{anonymous_name}]:\n#{cleaned_text}"
            sender_account = proxy_account
            application_to_use = nil
          end
        else
          Rails.logger.warn('Anonymous name generation returned nil, falling back to normal post')
          processed_text = original_text
          sender_account = current_user.account
          application_to_use = doorkeeper_token.application
        end
      else
        Rails.logger.warn('Anonymous proxy account not found, falling back to normal post')
        processed_text = original_text
        sender_account = current_user.account
        application_to_use = doorkeeper_token.application
      end
    else
      sender_account = current_user.account
      processed_text = original_text
      application_to_use = doorkeeper_token.application
    end

    begin
      if sender_account != current_user.account && status_params[:media_ids].present?
        transferred_media = current_user.account.media_attachments
                                        .where(status_id: nil)
                                        .where(id: status_params[:media_ids])
                                        .to_a

        transferred_media.each do |media|
          media.update!(account_id: sender_account.id)
        end
      end

      @status = PostStatusService.new.call(
        sender_account,
        text: processed_text,
        thread: @thread,
        quoted_status: @quoted_status,
        quote_approval_policy: quote_approval_policy,
        media_ids: status_params[:media_ids],
        sensitive: status_params[:sensitive],
        spoiler_text: status_params[:spoiler_text],
        visibility: status_params[:visibility],
        language: status_params[:language],
        scheduled_at: status_params[:scheduled_at],
        application: application_to_use,
        poll: status_params[:poll],
        content_type: status_params[:content_type],
        allowed_mentions: status_params[:allowed_mentions],
        idempotency: request.headers['Idempotency-Key'],
        with_rate_limit: true
      )
    rescue => e
      transferred_media.each do |media|
        begin
          media.reload
          media.update(account_id: current_user.account.id) if media.status_id.nil?
        rescue => rollback_error
          Rails.logger.error("Failed to rollback media ownership for media #{media.id}: #{rollback_error.message}")
        end
      end

      raise e
    end

    render json: @status, serializer: serializer_for_status
  rescue PostStatusService::UnexpectedMentionsError => e
    render json: unexpected_accounts_error_json(e), status: 422
  end

  def update
    @status = Status.where(account: current_account).find(params[:id])
    authorize @status, :update?

    UpdateStatusService.new.call(
      @status,
      current_account.id,
      text: status_params[:status],
      media_ids: status_params[:media_ids],
      media_attributes: status_params[:media_attributes],
      sensitive: status_params[:sensitive],
      language: status_params[:language],
      spoiler_text: status_params[:spoiler_text],
      poll: status_params[:poll],
      quote_approval_policy: quote_approval_policy,
      content_type: status_params[:content_type]
    )

    render json: @status, serializer: REST::StatusSerializer
  end

  def destroy
    @status = Status.where(account: current_account).find(params[:id])
    authorize @status, :destroy?

    json = render_to_body json: @status, serializer: REST::StatusSerializer, source_requested: true

    @status.discard_with_reblogs
    StatusPin.find_by(status: @status)&.destroy
    @status.account.statuses_count = @status.account.statuses_count - 1

    RemovalWorker.perform_async(@status.id, { 'redraft' => !truthy_param?(:delete_media) })

    render json: json
  end

  private

  def set_statuses
    @statuses = Status.permitted_statuses_from_ids(status_ids, current_account)
  end

  def set_status
    @status = Status.find(params[:id])
    authorize @status, :show?
  rescue Mastodon::NotPermittedError
    not_found
  end

  def set_thread
    @thread = Status.find(status_params[:in_reply_to_id]) if status_params[:in_reply_to_id].present?
    authorize(@thread, :show?) if @thread.present?
  rescue ActiveRecord::RecordNotFound, Mastodon::NotPermittedError
    render json: { error: I18n.t('statuses.errors.in_reply_not_found') }, status: 404
  end

  def set_quoted_status
    @quoted_status = Status.find(status_params[:quoted_status_id])&.proper if status_params[:quoted_status_id].present?
    authorize(@quoted_status, :quote?) if @quoted_status.present?
  rescue ActiveRecord::RecordNotFound, Mastodon::NotPermittedError
    # TODO: distinguish between non-existing and non-quotable posts
    render json: { error: I18n.t('statuses.errors.quoted_status_not_found') }, status: 404
  end

  def check_statuses_limit
    raise(Mastodon::ValidationError) if status_ids.size > DEFAULT_STATUSES_LIMIT
  end

  def status_ids
    Array(statuses_params[:id]).uniq.map(&:to_i)
  end

  def statuses_params
    params.permit(id: [])
  end

  def status_params
    params.permit(
      :status,
      :in_reply_to_id,
      :quoted_status_id,
      :quote_approval_policy,
      :sensitive,
      :spoiler_text,
      :visibility,
      :language,
      :scheduled_at,
      :content_type,
      allowed_mentions: [],
      media_ids: [],
      media_attributes: [
        :id,
        :thumbnail,
        :description,
        :focus,
      ],
      poll: [
        :multiple,
        :hide_totals,
        :expires_in,
        options: [],
      ]
    )
  end

  def serializer_for_status
    @status.is_a?(ScheduledStatus) ? REST::ScheduledStatusSerializer : REST::StatusSerializer
  end

  def unexpected_accounts_error_json(error)
    {
      error: error.message,
      unexpected_accounts: serialized_accounts(error.accounts),
    }
  end

  def serialized_accounts(accounts)
    ActiveModel::Serializer::CollectionSerializer.new(accounts, serializer: REST::AccountSerializer)
  end

  def should_post_anonymously?(text)
    anon_config = Rails.configuration.x.anon
    anon_config.enabled &&
      anon_config.account_username.present? &&
      anon_config.tag.present? &&
      text.strip.match?(/#{Regexp.escape(anon_config.tag)}(?:\s*#{Regexp.escape('👁')}\ufe0f?)?\s*\z/)
  end

  def generate_anonymous_name(account)
    anon_config = Rails.configuration.x.anon
    return nil unless anon_config.enabled && anon_config.account_username.present? && anon_config.name_list.any?

    period_hours = anon_config.period_hours
    current_time_utc = Time.current.utc
    hours_since_epoch = current_time_utc.to_i / 3600
    time_window = hours_since_epoch / period_hours

    mapping_key = "anon_names:#{time_window}:mapping"
    used_key = "anon_names:#{time_window}:used"

    existing_name = with_redis { |redis_conn| redis_conn.hget(mapping_key, account.username) }
    return existing_name if existing_name.present?

    input = "#{account.username}#{anon_config.salt}#{time_window}"
    start_index = Digest::SHA2.hexdigest(input).to_i(16) % anon_config.name_list.size

    with_redis do |redis_conn|
      name_list = anon_config.name_list

      name_list.size.times do |offset|
        index = (start_index + offset) % name_list.size
        candidate_name = name_list[index]

        next unless redis_conn.sadd(used_key, candidate_name) == 1

        redis_conn.hset(mapping_key, account.username, candidate_name)
        redis_conn.expire(mapping_key, (period_hours + 1) * 3600)
        redis_conn.expire(used_key, (period_hours + 1) * 3600)
        return candidate_name
      end

      base_name = name_list[start_index]
      used_count = redis_conn.scard(used_key)
      suffix_index = used_count % name_list.size
      suffix_name = name_list[suffix_index]
      combined_name = "#{base_name}#{suffix_name}"

      redis_conn.sadd(used_key, combined_name)
      redis_conn.hset(mapping_key, account.username, combined_name)
      redis_conn.expire(mapping_key, (period_hours + 1) * 3600)
      redis_conn.expire(used_key, (period_hours + 1) * 3600)

      combined_name
    end
  rescue Redis::BaseError => e
    Rails.logger.error("Anonymous name generation failed: #{e.message}")
    Rails.logger.error(e.backtrace.join("\n"))
    input = "#{account.username}#{anon_config.salt}#{time_window}"
    name_index = Digest::SHA2.hexdigest(input).to_i(16) % anon_config.name_list.size
    anon_config.name_list[name_index]
  end
end
