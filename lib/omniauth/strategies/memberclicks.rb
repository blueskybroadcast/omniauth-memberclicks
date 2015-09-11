require 'omniauth-oauth2'
require 'rest-client'

module OmniAuth
  module Strategies
    class Memberclicks < OmniAuth::Strategies::OAuth2
      option :name, 'memberclicks'

      option :client_options, {
        login_page_url: 'MUST BE SET',
        api_url: 'MUST BE SET',
        api_key: 'MUST BE SET'
      }

      uid { @raw_info[:uid] }

      info do
        {
          id: @raw_info[:uid],
          username: @raw_info[:username],
          email: @raw_info[:email],
          first_name: @raw_info[:first_name],
          last_name: @raw_info[:last_name],
          active_status: @raw_info[:active_status],
          npn_ce_id: @raw_info[:npn_ce_id],
          lcc: @raw_info[:lcc]
        }
      end

      extra do
        { :raw_info => @raw_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect login_page_url + "?redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        @raw_info ||= {
          :uid => request.params['uid'],
          :username => request.params['username'],
          :email => request.params['email'],
          :first_name => request.params['first_name'],
          :last_name => request.params['last_name'],
          :active_status => request.params['active_status'],
          :npn_ce_id => request.params['npn_ce_id'],
          :lcc => request.params['lcc']
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
        call_app!
      end

      def credentials
        {
          login_page_url: login_page_url,
          api_url: api_url,
          api_key: api_key
        }
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = credentials
        hash.extra = extra
        hash
      end

      private

      def login_page_url
        options.client_options.login_page_url
      end

      def api_url
        options.client_options.api_url
      end

      def api_key
        options.client_options.api_key
      end
    end
  end
end
