# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Anonymous posting configuration', type: :request do
  subject(:load_config) { load Rails.root.join('config', 'initializers', 'anonymous_posts.rb') }

  around do |example|
    original = Rails.configuration.x.anon
    Rails.configuration.x.anon = ActiveSupport::OrderedOptions.new
    ClimateControl.modify(ANON_ENABLED: 'true', ANON_TAG: '匿了', ANON_ACCOUNT: 'proxy', ANON_SALT: 'test', ANON_PERIOD: '24', ANON_NAMELIST_PATH: '/missing/anonymous-names') do
      example.run
    end
  ensure
    Rails.configuration.x.anon = original
  end

  it 'keeps anonymous intent enabled when a name file cannot be read' do
    load_config

    expect(Rails.configuration.x.anon.enabled).to be true
    expect(Rails.configuration.x.anon.error).to be_present
  end

  it 'rejects a blank marker at startup' do
    ClimateControl.modify(ANON_TAG: ' ') do
      expect { load_config }.to raise_error(ArgumentError, /ANON_TAG/)
    end
  end

  %w(0 -1 invalid 1.5).each do |period|
    it "marks period #{period} as unavailable" do
      ClimateControl.modify(ANON_PERIOD: period) { load_config }

      expect(Rails.configuration.x.anon.error).to include('ANON_PERIOD')
    end
  end

  ['匿了 ', ' 匿了', "匿了\n", "匿了\t"].product(%w(true false)).each do |tag, enabled|
    it "rejects marker #{tag.inspect} with ANON_ENABLED=#{enabled}" do
      ClimateControl.modify(ANON_TAG: tag, ANON_ENABLED: enabled) do
        expect { load_config }.to raise_error(ArgumentError, /ANON_TAG/)
      end
    end
  end

  it 'normalizes and deduplicates file entries' do
    allow(File).to receive(:readlines).with('/missing/anonymous-names').and_return([" Anon\n", "Anon\r\n", "\n", "Another\rName\n"])

    load_config

    expect(Rails.configuration.x.anon.name_list).to eq(['Anon', 'Another Name'])
    expect(Rails.configuration.x.anon.error).to be_nil
  end

  it 'does not require a name file when explicitly disabled' do
    ClimateControl.modify(ANON_ENABLED: 'false') { load_config }

    expect(Rails.configuration.x.anon.enabled).to be false
    expect(Rails.configuration.x.anon.error).to be_nil
    expect(Rails.configuration.x.anon.tag).to eq('匿了')
  end
end
