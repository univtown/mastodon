# frozen_string_literal: true

require 'rails_helper'

RSpec.describe AnonymousNameService do
  let(:account) { Account.new(id: 101, username: 'alice') }
  let(:config) { ActiveSupport::OrderedOptions.new.update(salt: 'test-salt', name_list: ['Anon'], period_hours: 24) }

  before { allow(Rails.configuration.x).to receive(:anon).and_return(config) }

  it 'keeps a stable name without storing the username or account ID as a field' do
    first = described_class.new.call(account)

    expect(described_class.new.call(account)).to eq(first)
    mapping = redis.keys('anon_names:v2:*:mapping').sole
    expect(redis.hkeys(mapping)).to all(match(/\A[0-9a-f]{64}\z/))
  end

  it 'normalizes and deduplicates display names, then allocates unique suffixes' do
    config.name_list = [" Anon\n", 'Anon', 'Anon-1', ' ']
    names = Array.new(6) { |index| described_class.new.call(Account.new(id: index + 1, username: "user#{index}")) }

    expect(names.uniq.size).to eq(6)
    expect(names).to include('Anon', 'Anon-1')
    expect(names).to all(match(/\AAnon(?:-\d+)*\z/))
  end

  it 'atomically reuses the same name for concurrent calls by one user' do
    workers = Array.new(8) { Thread.new { described_class.new.call(account) } }

    expect(workers.map(&:value).uniq).to eq(['Anon'])
    expect(redis.scard(redis.keys('anon_names:v2:*:used').sole)).to eq(1)
  end

  it 'allocates distinct names to concurrent users even after exhausting the list' do
    workers = Array.new(8) do |index|
      Thread.new { described_class.new.call(Account.new(id: index + 1, username: "user#{index}")) }
    end

    expect(workers.map(&:value).uniq.size).to eq(8)
  end

  [7, 24].each do |period_hours|
    context "with a #{period_hours}-hour period" do
      before { config.period_hours = period_hours }

      it 'changes windows at the epoch-aligned boundary without extending old expiry' do
        period = period_hours.hours.to_i
        boundary = ((redis.time.first / period) + 1) * period
        old_window = (boundary / period) - 1
        old_keys = ["anon_names:v2:#{old_window}:mapping", "anon_names:v2:#{old_window}:used"]

        travel_to(Time.at(boundary - 1).utc) { described_class.new.call(account) }

        expect(old_keys.map { |key| redis.expiretime(key) }).to all(eq(boundary + 3600))

        travel_to(Time.at(boundary).utc) { described_class.new.call(account) }

        new_keys = redis.keys('anon_names:v2:*') - old_keys
        expect(new_keys.size).to eq(2)
        expect(new_keys.map { |key| redis.expiretime(key) }).to all(eq(boundary + period + 3600))
        expect(old_keys.map { |key| redis.expiretime(key) }).to all(eq(boundary + 3600))
      end

      it 'actually expires both keys when their window deadline is past Redis time' do
        period = period_hours.hours.to_i
        expired_window = ((redis.time.first - 3600) / period) - 1
        keys = ["anon_names:v2:#{expired_window}:mapping", "anon_names:v2:#{expired_window}:used"]

        travel_to(Time.at(expired_window * period).utc) do
          expect(described_class.new.call(account)).to eq('Anon')
        end

        expect(keys.map { |key| redis.exists?(key) }).to all(be false)

        described_class.new.call(account)

        expect(redis.keys('anon_names:v2:*').size).to eq(2)
      end
    end
  end

  it 'does not fall back to an unreserved name on Redis failure' do
    allow(RedisConnection).to receive(:with).and_raise(Redis::BaseError)

    expect { described_class.new.call(account) }.to raise_error(Redis::BaseError)
  end
end
