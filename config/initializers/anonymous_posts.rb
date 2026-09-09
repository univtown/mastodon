# frozen_string_literal: true

Rails.application.configure do
  config.x.anon.enabled = ENV['ANON_ENABLED'] == 'true'
  config.x.anon.tag = ENV.fetch('ANON_TAG', '匿了')
  config.x.anon.account_username = ENV.fetch('ANON_ACCOUNT', nil)
  config.x.anon.namelist_path = ENV.fetch('ANON_NAMELIST_PATH', nil)
  config.x.anon.salt = ENV.fetch('ANON_SALT', nil)
  config.x.anon.period_hours = Integer(ENV.fetch('ANON_PERIOD', '24'), exception: false)
  config.x.anon.name_list = []

  raise ArgumentError, 'ANON_TAG must not be blank' if config.x.anon.tag.blank?
  raise ArgumentError, 'ANON_TAG must not have surrounding whitespace' if config.x.anon.tag != config.x.anon.tag.strip

  if config.x.anon.enabled
    begin
      raise ArgumentError, 'ANON_ACCOUNT must be configured' if config.x.anon.account_username.blank?
      raise ArgumentError, 'ANON_SALT must be configured' if config.x.anon.salt.blank?
      raise ArgumentError, 'ANON_PERIOD must be a positive integer' unless config.x.anon.period_hours&.positive?
      raise ArgumentError, 'ANON_NAMELIST_PATH must be configured' if config.x.anon.namelist_path.blank?

      config.x.anon.name_list = File.readlines(config.x.anon.namelist_path).map { |name| name.gsub(/\R+/, ' ').strip }.compact_blank.uniq
      raise ArgumentError, 'Anonymous name list must not be empty' if config.x.anon.name_list.empty?
    rescue ArgumentError, SystemCallError, IOError => e
      config.x.anon.error = e.message
      Rails.logger.error("Anonymous posting unavailable: #{e.message}")
    end
  end
end
