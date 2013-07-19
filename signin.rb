# Copyright 2013 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


##
# The Google+ Ruby Quickstart lets you get started with the Google+ platform
# in a few minutes.
#
# The app demonstrates:
#  * Using the Google+ Sign-In button to get an OAuth 2.0 refresh token.
#  * Exchanging the refresh token for an access token.
#  * Making Google+ API requests with the access token, including getting a
#    list of people that the user has circled.
#  * Disconnecting the app from the user's Google account and revoking tokens.
#
# Author: class@google.com (Gus Class)
require 'base64'
require 'rubygems'
require 'json'
require 'sinatra'
require 'google/api_client'
require 'google/api_client/client_secrets'
require 'net/https'
require 'uri'
use Rack::Session::Pool, :expire_after => 86400 # 1 day

# Configuration
# See the README.md for getting the OAuth 2.0 client ID and
# client secret.

# Configuration that you probably don't have to change
APPLICATION_NAME = 'Google+ Ruby Quickstart'
PLUS_LOGIN_SCOPE = 'https://www.googleapis.com/auth/plus.login'
set :port, 4567

# Build the global client
$credentials = Google::APIClient::ClientSecrets.load
$authorization = Signet::OAuth2::Client.new(
    :authorization_uri => $credentials.authorization_uri,
    :token_credential_uri => $credentials.token_credential_uri,
    :client_id => $credentials.client_id,
    :client_secret => $credentials.client_secret,
    :redirect_uri => $credentials.redirect_uris.first,
    :scope => PLUS_LOGIN_SCOPE)
$client = Google::APIClient.new


##
# Connect the user with Google+ and store the credentials.
post '/connect' do
  # Get the token from the session if available or exchange the authorization
  # code for a token.
  if !session[:token]
    # Make sure that the state we set on the client matches the state sent
    # in the request to protect against request forgery.
    if session[:state] == params[:state]
      # Upgrade the code into a token object.
      $authorization.code = request.body.read
      $authorization.fetch_access_token!
      $client.authorization = $authorization

      id_token = $client.authorization.id_token
      encoded_json_body = id_token.split('.')[1]
      # Base64 must be a multiple of 4 characters long, trailing with '='
      encoded_json_body += (['='] * (encoded_json_body.length % 4)).join('')
      json_body = Base64.decode64(encoded_json_body)
      body = JSON.parse(json_body)
      # You can read the Google user ID in the ID token.
      # "sub" represents the ID token subscriber which in our case
      # is the user ID. This sample does not use the user ID.
      gplus_id = body['sub']

      # Serialize and store the token in the user's session.
      token_pair = TokenPair.new
      token_pair.update_token!($client.authorization)
      session[:token] = token_pair
    else
      halt 401, 'The client state does not match the server state.'
    end
    status 200
  else
    content_type :json
    'Current user is already connected.'.to_json
  end
end


##
# An Example API call, list the people the user shared with this app.
get '/people' do
  # Check for stored credentials in the current user's session.
  if !session[:token]
    halt 401, 'User not connected.'
  end

  # Authorize the client and construct a Google+ service.
  $client.authorization.update_token!(session[:token].to_hash)
  plus = $client.discovered_api('plus', 'v1')

  # Get the list of people as JSON and return it.
  response = $client.execute!(plus.people.list,
      :collection => 'visible',
      :userId => 'me').body
  content_type :json
  response
end


##
# Disconnect the user by revoking the stored token and removing session objects.
post '/disconnect' do
  halt 401, 'No stored credentials' unless session[:token]

  # Use either the refresh or access token to revoke if present.
  token = session[:token].to_hash[:refresh_token]
  token = session[:token].to_hash[:access_token] unless token

  # You could reset the state at this point, but as-is it will still stay unique
  # to this user and we're avoiding resetting the client state.
  # session.delete(:state)
  session.delete(:token)

  # Send the revocation request and return the result.
  revokePath = 'https://accounts.google.com/o/oauth2/revoke?token=' + token
  uri = URI.parse(revokePath)
  request = Net::HTTP.new(uri.host, uri.port)
  request.use_ssl = true
  status request.get(uri.request_uri).code
end


##
# Fill out the templated variables in index.html.
get '/' do
  # Create a string for verification
  if !session[:state]
    state = (0...13).map{('a'..'z').to_a[rand(26)]}.join
    session[:state] = state
  end
  state = session[:state]

  response = File.read('index.html').sub(/[{]{2}\s*STATE\s*[}]{2}/, state)
  response = response.sub(/[{]{2}\s*CLIENT_ID\s*[}]{2}/, $credentials.client_id)
  response = response.sub(/[{]{2}\s*APPLICATION_NAME\s*[}]{2}/,
      APPLICATION_NAME)
end


##
# Serializes and deserializes the token.
class TokenPair
  @refresh_token
  @access_token
  @expires_in
  @issued_at

  def update_token!(object)
    @refresh_token = object.refresh_token
    @access_token = object.access_token
    @expires_in = object.expires_in
    @issued_at = object.issued_at
  end

  def to_hash
    return {
      :refresh_token => @refresh_token,
      :access_token => @access_token,
      :expires_in => @expires_in,
      :issued_at => Time.at(@issued_at)}
  end
end
