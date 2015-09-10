require 'omniauth-oauth2'
require 'multi_xml'
require 'rest-client'

module OmniAuth
  module Strategies
    class Memberclicks < OmniAuth::Strategies::OAuth2
      option :name, 'memberclicks'

      option :client_options, {
        authentication_url: 'MUST BE SET',
        authentication_endpoint: '/services/auth',
        api_key: 'MUST BE SET'
      }

      uid { @raw_info[:uid] }

      info do
        {
          id: @raw_info[:uid],
          first_name: @raw_info[:first_name],
          last_name: @raw_info[:last_name],
          email: @raw_info[:email]
        }
      end

      extra do
        { :raw_info => @raw_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authentication_url + authentication_endpoint + "?redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        @raw_info ||= {
          :uid => request.params['uid'],
          :first_name => request.params['first_name'],
          :last_name => request.params['last_name'],
          :email => request.params['email']
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
        call_app!
      end

      def credentials
        {
          authentication_url: authentication_url,
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

      def authentication_url
        options.client_options.authentication_url
      end

      def authentication_endpoint
        options.client_options.authentication_endpoint
      end

      def api_key
        options.client_options.api_key
      end
    end
  end
end
