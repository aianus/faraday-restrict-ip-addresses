require 'faraday'
module Faraday
  class RestrictIPAddresses < Faraday::Middleware
    VERSION = '0.1.1'
  end
end
