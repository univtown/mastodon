# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PostAnonymousStatusService do
  subject(:publish) { described_class.new.call(account, options) }

  let(:account) { Fabricate(:user).account }
  let(:proxy) { Fabricate(:user).account }
  let(:media) { Fabricate(:media_attachment, account: account) }
  let(:options) { { text: 'Hello 匿了', visibility: 'public' } }
  let(:config) do
    ActiveSupport::OrderedOptions.new.update(
      enabled: true, tag: '匿了', account_username: proxy.username,
      salt: 'test-salt', name_list: ['Anon'], period_hours: 24
    )
  end

  before { allow(Rails.configuration.x).to receive(:anon).and_return(config) }

  it 'publishes under the proxy without the application or marker' do
    options[:application] = Fabricate(:application)

    expect(publish).to have_attributes(account: proxy, application: nil, text: "Anon:\n\nHello")
  end

  it 'passes unmarked requests through unchanged' do
    options.merge!(text: '**Hello**', content_type: 'text/markdown', visibility: 'private')

    expect(publish).to have_attributes(account: account, text: '**Hello**', content_type: 'text/markdown', visibility: 'private')
  end

  it 'allows normal media-only posts' do
    options.merge!(text: nil, media_ids: [media.id])

    expect(publish.account).to eq(account)
  end

  it 'rejects a malformed marker without publishing under the real account' do
    config.tag = '匿了 '
    options[:text] = 'Hello 匿了 '

    expect { publish }.to raise_error(Mastodon::ValidationError, /marker/)
    expect(account.statuses).to be_empty
    expect(proxy.statuses).to be_empty
  end

  [{ enabled: false }, { error: 'Unreadable names' }, { salt: '' }, { name_list: [] }, { period_hours: 0 }, { period_hours: -1 }, { period_hours: nil }, { account_username: 'missing' }].each do |invalid|
    it "rejects anonymous publication with #{invalid}" do
      config.merge!(invalid)

      expect { publish }.to raise_error(Mastodon::ValidationError)
      expect(account.statuses).to be_empty
      expect(proxy.statuses).to be_empty
    end
  end

  ['匿了 👁', 'Hello 匿了 👁️'].each do |text|
    it "rejects the legacy suffix in #{text}" do
      options[:text] = text

      expect { publish }.to raise_error(Mastodon::ValidationError, /local_only/)
    end
  end

  %w(private direct).each do |visibility|
    it "rejects #{visibility} visibility" do
      options[:visibility] = visibility

      expect { publish }.to raise_error(Mastodon::ValidationError, /public or unlisted/)
    end
  end

  it 'rejects private user defaults rather than widening the audience' do
    account.user.update!(settings: { default_privacy: 'private' })
    options.delete(:visibility)

    expect { publish }.to raise_error(Mastodon::ValidationError, /public or unlisted/)
  end

  it 'keeps user defaults and explicit local-only publication' do
    account.user.update!(settings: { default_privacy: 'unlisted', default_content_type: 'text/markdown', default_language: 'zh-CN', default_sensitive: true })
    options.delete(:visibility)
    options[:local_only] = true

    expect(publish).to have_attributes(visibility: 'unlisted', content_type: 'text/markdown', language: 'zh-CN', sensitive: true, local_only: true)
  end

  it 'rejects an unavailable proxy' do
    proxy.user.update!(disabled: true)

    expect { publish }.to raise_error(Mastodon::ValidationError, /unavailable/)
  end

  it 'rejects scheduling before transferring media' do
    options.merge!(scheduled_at: 1.hour.from_now, media_ids: [media.id])

    expect { publish }.to raise_error(Mastodon::ValidationError, /scheduled/)
    expect(media.reload).to have_attributes(account: account, status: nil)
  end

  it 'allows anonymous media-only posts and transfers ownership' do
    options.merge!(text: '匿了', media_ids: [media.id])

    status = publish

    expect(media.reload).to have_attributes(account: proxy, status: status)
  end

  it 'allows a quote without additional text' do
    options.merge!(text: '匿了', quoted_status: Fabricate(:status, visibility: :public, quote_approval_policy: InteractionPolicy::POLICY_FLAGS[:public] << 16))

    expect(publish.quote).to be_present
  end

  it 'rejects a marker without content' do
    options[:text] = '匿了'

    expect { publish }.to raise_error(Mastodon::ValidationError, /content cannot be empty/)
  end

  it 'does not treat malformed media IDs as content' do
    options.merge!(text: '匿了', media_ids: 'invalid')

    expect { publish }.to raise_error(Mastodon::ValidationError, /content cannot be empty/)
  end

  it 'rejects private quotes even when the proxy can quote them' do
    options[:quoted_status] = Fabricate(:status, account: proxy, visibility: :private)

    expect { publish }.to raise_error(Mastodon::ValidationError, /cannot quote private/)
  end

  %i(proxy stranger).each do |owner|
    it "rejects unattached media belonging to #{owner}" do
      media.update!(account: owner == :proxy ? proxy : Fabricate(:account))
      options[:media_ids] = [media.id]

      expect { publish }.to raise_error(Mastodon::ValidationError)
      expect(media.reload.status).to be_nil
    end
  end

  it 'keeps media ownership on validation failure' do
    options.merge!(text: "#{'a' * StatusLengthValidator::MAX_CHARS} 匿了", media_ids: [media.id])

    expect { publish }.to raise_error(ActiveRecord::RecordInvalid)
    expect(media.reload).to have_attributes(account: account, status: nil)
  end

  it 'rolls back the status and attachments when ownership transfer fails' do
    options[:media_ids] = [media.id]
    allow(MediaAttachment).to receive(:_update_record).and_wrap_original do |original, attributes, *arguments|
      raise ActiveRecord::RecordInvalid if attributes['account_id']&.value_for_database == proxy.id

      original.call(attributes, *arguments)
    end

    expect { publish }.to raise_error(ActiveRecord::RecordInvalid)
    expect(proxy.statuses).to be_empty
    expect(media.reload).to have_attributes(account: account, status: nil)
  end

  it 'keeps media ownership when antispam silently drops the post' do
    options[:media_ids] = [media.id]
    allow(Antispam).to receive(:new).and_wrap_original do |original, status|
      original.call(status).tap do |antispam|
        allow(antispam).to receive(:local_preflight_check!).and_raise(Antispam::SilentlyDrop.new(status))
      end
    end

    publish

    expect(media.reload).to have_attributes(account: account, status: nil)
    expect(proxy.statuses).to be_empty
  end

  context 'with a quote and media' do
    before do
      options.merge!(media_ids: [media.id], quoted_status: Fabricate(:status, visibility: :public, quote_approval_policy: InteractionPolicy::POLICY_FLAGS[:public] << 16))
    end

    it 'rolls back the status, quote and attachments when ownership transfer fails' do
      allow(MediaAttachment).to receive(:_update_record).and_wrap_original do |original, attributes, *arguments|
        raise ActiveRecord::RecordInvalid if attributes['account_id']&.value_for_database == proxy.id

        original.call(attributes, *arguments)
      end

      expect { publish }.to raise_error(ActiveRecord::RecordInvalid)
      expect(proxy.statuses).to be_empty
      expect(Quote.where(account: proxy)).to be_empty
      expect(media.reload).to have_attributes(account: account, status: nil)
    end

    it 'rolls back the quote and attachments when antispam silently drops the post' do
      allow(Antispam).to receive(:new).and_wrap_original do |original, status|
        original.call(status).tap do |antispam|
          allow(antispam).to receive(:local_preflight_check!).and_raise(Antispam::SilentlyDrop.new(status))
        end
      end

      publish

      expect(proxy.statuses).to be_empty
      expect(Quote.where(account: proxy)).to be_empty
      expect(media.reload).to have_attributes(account: account, status: nil)
    end
  end

  ['https://banned.example', 'https://banned.example 匿了'].each do |text|
    it "preserves the spam report without persisting a post, quote or media transfer for #{text}", use_transactional_tests: false do
      publisher = text.end_with?('匿了') ? proxy : account
      options.merge!(text: text, media_ids: [media.id], quoted_status: Fabricate(:status, visibility: :public, quote_approval_policy: InteractionPolicy::POLICY_FLAGS[:public] << 16))
      redis.sadd('antispam:all_time_spammy_texts', 'https://banned.example')

      publish

      expect(Account.representative.reports.spam.where(target_account: publisher).count).to eq(1)
      expect(Status.where(account: publisher)).to_not exist
      expect(Quote.where(account: publisher)).to be_empty
      expect(media.reload).to have_attributes(account: account, status: nil)
    ensure
      restore_test_database
    end
  end

  %i(thread quoted_status).each do |target|
    it "rejects #{target} inaccessible to the proxy" do
      options[target] = Fabricate(:status, account: account, visibility: :private)

      expect { publish }.to raise_error(Mastodon::NotPermittedError)
    end
  end

  it 'rejects Redis failure without publishing under the real account' do
    allow(AnonymousNameService).to receive(:new).and_return(instance_double(AnonymousNameService, call: nil))
    allow(AnonymousNameService.new).to receive(:call).and_raise(Redis::BaseError)

    expect { publish }.to raise_error(Mastodon::ValidationError, /unavailable/)
    expect(account.statuses).to be_empty
  end

  it 'returns the same status on a retry with already transferred media' do
    options.merge!(idempotency: 'same-key', media_ids: [media.id])
    first = publish

    expect(described_class.new.call(account, options).id).to eq(first.id)
    expect(proxy.statuses.count).to eq(1)
    expect(media.reload).to have_attributes(account: proxy, status: first)
  end

  it 'isolates users sharing an idempotency key without plaintext identities' do
    options[:idempotency] = 'same-key'
    first = publish
    second = described_class.new.call(Fabricate(:user).account, options)

    expect(first.id).to_not eq(second.id)
    expect(redis.keys('idempotency:status:*')).to all(match(/\Aidempotency:status:#{proxy.id}:[0-9a-f]{64}\z/))
  end

  it 'serializes concurrent retries of the same post', use_transactional_tests: false do
    options[:idempotency] = 'concurrent-key'
    account_id = account.id
    proxy_id = proxy.id
    barrier = Concurrent::CyclicBarrier.new(2)
    workers = Array.new(2) do
      Thread.new do
        ActiveRecord::Base.connection_pool.with_connection do
          requester = Account.find(account_id)
          barrier.wait
          publish_or_retry(requester)
        end
      end
    end
    results = workers.filter_map(&:value)

    expect(results.uniq.size).to eq(1)
    expect(Status.where(account_id: proxy_id).count).to eq(1)
    expect(described_class.new.call(account, options).id).to eq(results.first)
  ensure
    workers&.each(&:join)
    restore_test_database
  end

  it 'reads legacy idempotency without extending its lifetime' do
    status = Fabricate(:status, account: proxy)
    options[:idempotency] = 'old-key'
    key = "idempotency:status:#{account.id}:old-key"
    redis.setex(key, 60, status.id)

    expect(publish.id).to eq(status.id)
    expect(redis.ttl(key)).to be <= 60
    expect(redis.keys('anon_names:v2:*')).to be_empty
  end

  it 'ignores a legacy key pointing to another author' do
    status = Fabricate(:status, account: account)
    options[:idempotency] = 'old-key'
    redis.setex("idempotency:status:#{account.id}:old-key", 60, status.id)

    expect(publish.account).to eq(proxy)
  end

  def publish_or_retry(requester)
    described_class.new.call(requester, options).id
  rescue Mastodon::RaceConditionError
    nil
  end

  def restore_test_database
    DatabaseCleaner.clean
    Rails.application.load_seed
    Setting.registrations_mode = 'open'
  end
end
