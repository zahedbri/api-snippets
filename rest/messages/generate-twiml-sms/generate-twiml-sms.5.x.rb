require 'twilio-ruby'
require 'sinatra'

# Respond to incoming calls with a simple text message
post '/sms' do
  twiml = Twilio::TwiML::Response.new do |r|
    r.Message 'The Robots are coming! Head for the hills!'
  end

  content_type 'text/xml'
  # Return twml string
  twiml.text
end
