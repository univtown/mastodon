# frozen_string_literal: true

class PostAnonymousStatusService < BaseService
  include Redisable

  def call(account, options = {})
    @config = Rails.configuration.x.anon
    text = options[:text].to_s.strip

    raise Mastodon::ValidationError, 'Anonymous posting marker is not configured' if @config.tag.blank?
    raise Mastodon::ValidationError, 'Anonymous posting marker must not have surrounding whitespace' if @config.tag != @config.tag.strip
    raise Mastodon::ValidationError, 'The anonymous eye suffix is no longer supported; use local_only instead' if text.match?(/#{Regexp.escape(@config.tag)}\s*👁\ufe0f?\z/)

    return PostStatusService.new.call(account, options) unless text.end_with?(@config.tag)

    publish_anonymously(account, options, text)
  end

  private

  def publish_anonymously(account, options, text)
    validate_configuration!
    raise Mastodon::ValidationError, 'Anonymous posts cannot be scheduled' if options[:scheduled_at].present?

    anonymous_account = Account.find_local(@config.account_username)
    raise Mastodon::ValidationError, 'Anonymous posting is temporarily unavailable' unless anonymous_account&.user&.functional?

    previous_status = legacy_status(account, anonymous_account, options[:idempotency])
    return previous_status if previous_status

    anonymous_options = posting_options(account, options)
    raise Mastodon::ValidationError, 'Anonymous posts must be public or unlisted' unless %w(public unlisted).include?(anonymous_options[:visibility].to_s)
    raise Mastodon::NotPermittedError if options[:thread].present? && !StatusPolicy.new(anonymous_account, options[:thread]).show?
    raise Mastodon::NotPermittedError if options[:quoted_status].present? && !StatusPolicy.new(anonymous_account, options[:quoted_status]).quote?
    raise Mastodon::ValidationError, 'Anonymous posts cannot quote private statuses' if options[:quoted_status]&.private_visibility?

    cleaned_text = text.delete_suffix(@config.tag).strip
    has_media = options[:media_ids].is_a?(Enumerable) && options[:media_ids].present?
    raise Mastodon::ValidationError, 'Anonymous post content cannot be empty' if cleaned_text.blank? && !has_media && options[:quoted_status].blank?

    name = AnonymousNameService.new.call(account)
    anonymous_options.merge!(text: "#{name}:\n\n#{cleaned_text}", application: nil, media_owner: account)
    anonymous_options[:idempotency] = OpenSSL::HMAC.hexdigest('SHA256', @config.salt, "anonymous/status/v2:#{account.id}:#{options[:idempotency]}") if options[:idempotency].present?

    PostStatusService.new.call(anonymous_account, anonymous_options)
  rescue Redis::BaseError
    raise Mastodon::ValidationError, 'Anonymous posting is temporarily unavailable'
  end

  def validate_configuration!
    raise Mastodon::ValidationError, 'Anonymous posting is disabled' unless @config.enabled
    raise Mastodon::ValidationError, 'Anonymous posting is temporarily unavailable' if @config.error.present? || @config.account_username.blank? || @config.salt.blank? || @config.name_list.blank? || !@config.period_hours.is_a?(Integer) || !@config.period_hours.positive?
  end

  def posting_options(account, options)
    options.merge(
      content_type: options[:content_type].presence || account.user.setting_default_content_type,
      visibility: options[:visibility].presence || account.user.setting_default_privacy,
      language: options[:language].presence || account.user.preferred_posting_language,
      sensitive: options[:sensitive].nil? ? account.user.setting_default_sensitive : options[:sensitive]
    )
  end

  def legacy_status(account, anonymous_account, key)
    return if key.blank?

    status_id = with_redis { |connection| connection.get("idempotency:status:#{account.id}:#{key}") }
    anonymous_account.statuses.find_by(id: status_id) if status_id.present?
  end
end
