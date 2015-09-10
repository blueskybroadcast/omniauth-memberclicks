require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Memberclicks < OmniAuth::Strategies::OAuth2
      option :name, 'memberclicks'

      option :client_options, {
        authorize_url: 'MUST BE SET',
        access_key_id: 'MUST BE SET',
        secret_access_key: 'MUST BE SET',
        association_id: 'MUST BE SET'
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
        redirect authorize_url + "?redirectURL=" + callback_url + "?slug=#{slug}"
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
          authorize_url: authorize_url,
          access_key_id: access_key_id,
          secret_access_key: secret_access_key,
          association_id: association_id
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

      def authorize_url
        options.client_options.authorize_url
      end

      def access_key_id
        options.client_options.access_key_id
      end

      def secret_access_key
        options.client_options.secret_access_key
      end

      def association_id
        options.client_options.association_id
      end
    end
  end
end
