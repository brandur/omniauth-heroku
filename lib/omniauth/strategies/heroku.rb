require 'omniauth-oauth2'
require 'securerandom'

module OmniAuth
  module Strategies
    class Heroku < OmniAuth::Strategies::OAuth2
      BaseAuthUrl = ENV["HEROKU_AUTH_URL"] || "https://api.heroku.com"

      option :client_options, {
        :authorize_url => "#{BaseAuthUrl}/oauth/authorize",
        :site => BaseAuthUrl,
        :token_url => "#{BaseAuthUrl}/oauth/token"
      }

      def request_phase
        request_id = SecureRandom.uuid
        options[:connection_opts] = { :headers => {
          "Request-ID" => request_id
        } }
        log :info, "Request-ID for OAuth negotiation: #{request_id}"
        super
      end
    end
  end
end
