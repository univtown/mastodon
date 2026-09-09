# frozen_string_literal: true

class AnonymousNameService < BaseService
  include Redisable

  RESERVE_NAME = <<~LUA
    local existing = redis.call('HGET', KEYS[1], ARGV[1])
    if existing then return existing end
    if redis.call('SADD', KEYS[2], ARGV[2]) == 0 then return false end
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
    redis.call('EXPIREAT', KEYS[1], ARGV[3])
    redis.call('EXPIREAT', KEYS[2], ARGV[3])
    return ARGV[2]
  LUA

  def call(account)
    config = Rails.configuration.x.anon
    names = config.name_list.map { |name| name.gsub(/\R+/, ' ').strip }.compact_blank.uniq
    raise Mastodon::ValidationError, 'Anonymous posting is temporarily unavailable' if names.empty?

    period = config.period_hours * 3600
    window = Time.current.to_i / period
    expires_at = ((window + 1) * period) + 3600
    keys = ["anon_names:v2:#{window}:mapping", "anon_names:v2:#{window}:used"]
    identity = OpenSSL::HMAC.hexdigest('SHA256', config.salt, "anonymous/name/v2:#{account.id}")
    start_index = Digest::SHA256.hexdigest("#{account.username}#{config.salt}#{window}").to_i(16) % names.size

    with_redis do |connection|
      names.size.times do |offset|
        candidate = names[(start_index + offset) % names.size]
        reserved = connection.eval(RESERVE_NAME, keys: keys, argv: [identity, candidate, expires_at])
        return reserved if reserved
      end

      suffix = 1
      loop do
        candidate = "#{names[start_index]}-#{suffix}"
        reserved = connection.eval(RESERVE_NAME, keys: keys, argv: [identity, candidate, expires_at])
        return reserved if reserved

        suffix += 1
      end
    end
  end
end
