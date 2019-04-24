# This example uses the rest-client gem, https://github.com/rest-client/rest-client
require 'rest-client'

# Used for creating signatures
require 'openssl'
require 'Base64'

module Detectify
  # Base endpoint to the Detectify API, no trailing slash
  ENDPOINT = 'https://api.detectify.com/rest'.freeze

  # Generates signature headers. Returns a map of headers to pass along with the call.
  def self.signature(api_key, secret_key, method, url, timestamp, body='')
    method = method.upcase
    data = "#{method};#{url};#{api_key};#{timestamp};#{body}"
    secret = Base64.decode64(secret_key)

    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), secret, data)
    sig = Base64.encode64(hmac).strip

    {
      'X-Detectify-Signature': sig,
      'X-Detectify-Timestamp': timestamp
    }
  end

  # Creates the headers used for API calls.
  def self.create_headers(method, path, api_key, secret_key = nil)
    headers = { 'X-Detectify-Key': api_key }

    # Create the signature headers if a secret key is used
    unless secret_key.nil?
      timestamp = Time.now.to_i
      headers.merge!(Detectify::signature(api_key, secret_key, method, path, timestamp))
    end

    headers
  end

  # Starts a new scan on the provided scan profile. Returns true if the scan was started,
  # false if it was not started.
  def self.start_scan(scan_profile, api_key, secret_key=nil)
    path = "/v2/scans/#{scan_profile}/"
    url = "#{ENDPOINT}#{path}"

    # Create headers for the call
    headers = create_headers('POST', path, api_key, secret_key)

    # Make the API call
    RestClient.post(url, '', headers) do |response, _request, _result, &_block|
      case response.code
        when 202
          puts 'Scan start request accepted'
          true
        when 400
          puts 'Invalid scan profile token'
          false
        when 401
          puts 'Missing/invalid API key or message signature, or invalid timestamp'
          false
        when 403
          puts 'The API key cannot access this functionality'
          false
        when 404
          puts 'The specified scan profile does not exist or the API cannot access the profile'
          false
        when 409
          puts 'A scan is already running on the specified profile'
          false
        when 423
          puts 'The domain is not verified'
          false
        when 500, 503
          puts 'An error occurred while processing the request'
          false
        else
          puts "Unhandled response, Got code #{response.code}"
          puts response.body
          false
      end
    end
  end

  # Prints the status of a currently running scan.
  def self.scan_status(scan_profile, api_key, secret_key = nil)
    path = "/v2/scans/#{scan_profile}/"
    url = "#{ENDPOINT}#{path}"

    # Create headers for the call
    headers = create_headers('GET', path, api_key, secret_key)

    # Make the call
    RestClient.get(url, headers) do |response, _request, _result, &_block|
      case response.code
        when 200
          puts response.body
        when 400
          puts 'Invalid scan profile token'
        when 401
          puts 'Missing/invalid API key or message signature, or invalid timestamp'
        when 403
          puts 'The API key cannot access this functionality'
        when 404
          puts 'No scan running for the specified profile, or the specified scan profile does not exist, or the API cannot access the profile'
        when 500, 503
          puts 'An error occurred while processing the request'
        else
          puts "Unhandled API response, got code #{response.code}"
          puts response.body
      end
    end
  end
end

# Example API key, secret key and scan profile token
API_KEY = 'd4bf676ee6146557cbf0f28fe6cbc290'.freeze
SECRET_KEY = 'SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ=='.freeze
SCAN_PROFILE = '5605b488634efe810dff4276e28ca7f9'.freeze

# Start a new scan using a secret key
scan_started = Detectify.start_scan(SCAN_PROFILE, API_KEY, SECRET_KEY)

# Get status if it was successfully started
Detectify.scan_status(SCAN_PROFILE, API_KEY, SECRET_KEY) if scan_started
