require 'devise'
require 'devise_cosign_authenticatable/schema'
require 'devise_cosign_authenticatable/routes'
require 'devise_cosign_authenticatable/strategy'
require 'devise_cosign_authenticatable/exceptions'
require 'devise_cosign_authenticatable/single_sign_out'
require 'devise_cosign_authenticatable/railtie' if defined?(Rails::Railtie)

# Register as a Rails engine
module DeviseCosignAuthenticatable
  class Engine < Rails::Engine
    initializer "devise_cosign_authenticatable.single_sign_on.warden_failure_app" do |app|
      # requiring this here because the parent class calls Rails.application, which
      # isn't set up until after bundler has required the modules in this engine
      require 'devise_cosign_authenticatable/single_sign_out/warden_failure_app'
    end
  end
end

module Devise
  # The base URL of the COSIGN server.  For example, http://cosign.example.com.  Specifying this
  # is mandatory.
  @@cosign_base_url = nil

  # The login URL of the COSIGN server.  If undefined, will default based on cosign_base_url.
  @@cosign_login_url = nil

  # The login URL of the COSIGN server.  If undefined, will default based on cosign_base_url.
  @@cosign_logout_url = nil

  # The login URL of the COSIGN server.  If undefined, will default based on cosign_base_url.
  @@cosign_validate_url = nil

  # The destination url for logout.
  @@cosign_destination_url = nil

  # The follow url for logout.
  @@cosign_follow_url = nil

  # Which url to send with logout, destination or follow. Can either be nil, destination or follow.
  @@cosign_logout_url_param = nil

  # Should devise_cosign_authenticatable enable single-sign-out? Requires use of a supported
  # session_store. Currently supports active_record or redis.
  # False by default.
  @@cosign_enable_single_sign_out = false

  # What strategy should single sign out use for tracking token->session ID mapping.
  # :rails_cache by default.
  @@cosign_single_sign_out_mapping_strategy = :rails_cache

  # Should devise_cosign_authenticatable attempt to create new user records for
  # unknown usernames?  True by default.
  @@cosign_create_user = true

  # The model attribute used for query conditions. Should be the same as
  # the rubycosign-server username_column. :username by default
  @@cosign_username_column = :username

  # Name of the parameter passed in the logout query
  @@cosign_destination_logout_param_name = nil

  # Additional options for COSIGN client object
  @@cosign_client_config_options = {}

  mattr_accessor :cosign_base_url, :cosign_login_url, :cosign_logout_url, :cosign_validate_url, :cosign_destination_url, :cosign_follow_url, :cosign_logout_url_param, :cosign_create_user, :cosign_destination_logout_param_name, :cosign_username_column, :cosign_enable_single_sign_out, :cosign_single_sign_out_mapping_strategy, :cosign_client_config_options

  def self.cosign_create_user?
    cosign_create_user
  end

  # Return a COSIGNClient::Client instance based on configuration parameters.
  def self.cosign_client
    @@cosign_client ||= begin
      cosign_options = {
        :cosign_destination_logout_param_name => @@cosign_destination_logout_param_name,
        :cosign_base_url => @@cosign_base_url,
        :login_url => @@cosign_login_url,
        :logout_url => @@cosign_logout_url,
        :validate_url => @@cosign_validate_url,
        :enable_single_sign_out => @@cosign_enable_single_sign_out
      }

      cosign_options.merge!(@@cosign_client_config_options) if @@cosign_client_config_options

      COSIGNClient::Client.new(cosign_options)
    end
  end

  def self.cosign_service_url(base_url, mapping)
    cosign_action_url(base_url, mapping, "service")
  end

  def self.cosign_unregistered_url(base_url, mapping)
    cosign_action_url(base_url, mapping, "unregistered")
  end

  private
  def self.cosign_action_url(base_url, mapping, action)
    u = URI.parse(base_url)
    u.query = nil
    u.path = if mapping.respond_to?(:fullpath)
      if ENV['RAILS_RELATIVE_URL_ROOT']
        ENV['RAILS_RELATIVE_URL_ROOT'] + mapping.fullpath
      else
        mapping.fullpath
      end
    else
      if ENV['RAILS_RELATIVE_URL_ROOT']
        ENV['RAILS_RELATIVE_URL_ROOT'] + mapping.raw_path
      else
        mapping.raw_path
      end
    end
    u.path << "/" unless u.path =~ /\/$/
    u.path << action
    u.to_s
  end
end

Devise.add_module(:cosign_authenticatable,
                  :strategy => true,
                  :controller => :cosign_sessions,
                  :route => :cosign_authenticatable,
                  :model => 'devise_cosign_authenticatable/model')

module COSIGNClient
  # The client brokers all HTTP transactions with the CAS server.
  class Client
    attr_reader :cas_base_url, :cas_destination_logout_param_name
    attr_reader :log, :username_session_key, :extra_attributes_session_key
    attr_reader :ticket_store
    attr_reader :proxy_host, :proxy_port
    attr_writer :login_url, :validate_url, :proxy_url, :logout_url, :service_url
    attr_accessor :proxy_callback_url, :proxy_retrieval_url

    def initialize(conf = nil)
      configure(conf) if conf
    end

    def configure(conf)
      #TODO: raise error if conf contains unrecognized cas options (this would help detect user typos in the config)

      raise ArgumentError, "Missing :cas_base_url parameter!" unless conf[:cas_base_url]

      if conf.has_key?("encode_extra_attributes_as")
        unless (conf[:encode_extra_attributes_as] == :json || conf[:encode_extra_attributes_as] == :yaml)
          raise ArgumentError, "Unkown Value for :encode_extra_attributes_as parameter! Allowed options are json or yaml - #{conf[:encode_extra_attributes_as]}"
        end
      end

      @cas_base_url      = conf[:cas_base_url].gsub(/\/$/, '')
      @cas_destination_logout_param_name = conf[:cas_destination_logout_param_name]

      @login_url    = conf[:login_url]
      @logout_url   = conf[:logout_url]
      @validate_url = conf[:validate_url]
      @proxy_url    = conf[:proxy_url]
      @service_url  = conf[:service_url]
      @force_ssl_verification  = conf[:force_ssl_verification]
      @proxy_callback_url  = conf[:proxy_callback_url]

      #proxy server settings
      @proxy_host = conf[:proxy_host]
      @proxy_port = conf[:proxy_port]

      @username_session_key         = conf[:username_session_key] || :cas_user
      @extra_attributes_session_key = conf[:extra_attributes_session_key] || :cas_extra_attributes
      @ticket_store_class = case conf[:ticket_store]
                            when :local_dir_ticket_store, nil
                              CASClient::Tickets::Storage::LocalDirTicketStore
                            when :active_record_ticket_store
                              require 'casclient/tickets/storage/active_record_ticket_store'
                              CASClient::Tickets::Storage::ActiveRecordTicketStore
                            else
                              conf[:ticket_store]
                            end
      @ticket_store = @ticket_store_class.new conf[:ticket_store_config]
      raise CosignException, "The Ticket Store is not a subclass of AbstractTicketStore, it is a #{@ticket_store_class}" unless @ticket_store.kind_of? CASClient::Tickets::Storage::AbstractTicketStore

      @log = CASClient::LoggerWrapper.new
      @log.set_real_logger(conf[:logger]) if conf[:logger]
      @ticket_store.log = @log
      @conf_options = conf
    end

    def cas_destination_logout_param_name
      @cas_destination_logout_param_name || "destination"
    end

    def login_url
      @login_url || (cas_base_url + "/login")
    end

    def validate_url
      @validate_url || (cas_base_url + "/proxyValidate")
    end

    # Returns the CAS server's logout url.
    #
    # If a logout_url has not been explicitly configured,
    # the default is cas_base_url + "/logout".
    #
    # destination_url:: Set this if you want the user to be
    #                   able to immediately log back in. Generally
    #                   you'll want to use something like <tt>request.referer</tt>.
    #                   Note that the above behaviour describes RubyCAS-Server
    #                   -- other CAS server implementations might use this
    #                   parameter differently (or not at all).
    # follow_url:: This satisfies section 2.3.1 of the CAS protocol spec.
    #              See http://www.ja-sig.org/products/cas/overview/protocol
    def logout_url(destination_url = nil, follow_url = nil, service_url = nil)
      url = @logout_url || (cas_base_url + "/logout")
      uri = URI.parse(url)
      service_url = (service_url if service_url) || @service_url
      h = uri.query ? query_to_hash(uri.query) : {}

      if destination_url
        # if present, remove the 'ticket' parameter from the destination_url
        duri = URI.parse(destination_url)
        dh = duri.query ? query_to_hash(duri.query) : {}
        dh.delete('ticket')
        duri.query = hash_to_query(dh)
        destination_url = duri.to_s.gsub(/\?$/, '')
        h[cas_destination_logout_param_name] = destination_url if destination_url
        h['gateway'] = 'true'
      elsif follow_url
        h['url'] = follow_url if follow_url
        h['service'] = service_url
      else
        h['service'] = service_url
      end
      uri.query = hash_to_query(h)
      uri.to_s
    end

    def proxy_url
      @proxy_url || (cas_base_url + "/proxy")
    end

    def validate_service_ticket(st)
      uri = URI.parse(validate_url)
      h = uri.query ? query_to_hash(uri.query) : {}
      h['service'] = st.service
      h['ticket'] = st.ticket
      h['renew'] = "1" if st.renew
      h['pgtUrl'] = proxy_callback_url if proxy_callback_url
      uri.query = hash_to_query(h)

      response = request_cas_response(uri, ValidationResponse)
      st.user = response.user
      st.extra_attributes = response.extra_attributes
      st.pgt_iou = response.pgt_iou
      st.success = response.is_success?
      st.failure_code = response.failure_code
      st.failure_message = response.failure_message

      return st
    end
    alias validate_proxy_ticket validate_service_ticket

    # Returns true if the configured CAS server is up and responding;
    # false otherwise.
    def cas_server_is_up?
      uri = URI.parse(login_url)

      log.debug "Checking if CAS server at URI '#{uri}' is up..."

      https = https_connection(uri)

      begin
        raw_res = https.start do |conn|
          conn.get("#{uri.path}?#{uri.query}")
        end
      rescue Errno::ECONNREFUSED => e
        log.warn "CAS server did not respond! (#{e.inspect})"
        return false
      end

      log.debug "CAS server responded with #{raw_res.inspect}:\n#{raw_res.body}"

      return raw_res.kind_of?(Net::HTTPSuccess)
    end

    # Requests a login using the given credentials for the given service;
    # returns a LoginResponse object.
    def login_to_service(credentials, service)
      lt = request_login_ticket

      data = credentials.merge(
          :lt => lt,
          :service => service
      )

      res = submit_data_to_cas(login_url, data)
      response = CASClient::LoginResponse.new(res)

      if response.is_success?
        log.info("Login was successful for ticket: #{response.ticket.inspect}.")
      end

      return response
    end

    # Requests a login ticket from the CAS server for use in a login request;
    # returns a LoginTicket object.
    #
    # This only works with RubyCAS-Server, since obtaining login
    # tickets in this manner is not part of the official CAS spec.
    def request_login_ticket
      uri = URI.parse(login_url+'Ticket')
      https = https_connection(uri)
      res = https.post(uri.path, ';')

      raise CosignException, res.body unless res.kind_of? Net::HTTPSuccess

      res.body.strip
    end

    # Requests a proxy ticket from the CAS server for the given service
    # using the given pgt (proxy granting ticket); returns a ProxyTicket
    # object.
    #
    # The pgt required to request a proxy ticket is obtained as part of
    # a ValidationResponse.
    def request_proxy_ticket(pgt, target_service)
      uri = URI.parse(proxy_url)
      h = uri.query ? query_to_hash(uri.query) : {}
      h['pgt'] = pgt.ticket
      h['targetService'] = target_service
      uri.query = hash_to_query(h)

      response = request_cas_response(uri, ProxyResponse)

      pt = ProxyTicket.new(response.proxy_ticket, target_service)
      pt.success = response.is_success?
      pt.failure_code = response.failure_code
      pt.failure_message = response.failure_message

      return pt
    end

    def retrieve_proxy_granting_ticket(pgt_iou)
      pgt = @ticket_store.retrieve_pgt(pgt_iou)

      raise CosignException, "Couldn't find pgt for pgt_iou #{pgt_iou}" unless pgt

      ProxyGrantingTicket.new(pgt, pgt_iou)
    end

    def add_service_to_login_url(service_url)
      uri = URI.parse(login_url)
      uri.query = (uri.query ? uri.query + "&" : "") + "service=#{CGI.escape(service_url)}"
      uri.to_s
    end

    private

    def https_connection(uri)
      https = Net::HTTP::Proxy(proxy_host, proxy_port).new(uri.host, uri.port)
      https.use_ssl = (uri.scheme == 'https')
      https.verify_mode = (@force_ssl_verification ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE)
      https
    end

    # Fetches a CAS response of the given type from the given URI.
    # Type should be either ValidationResponse or ProxyResponse.
    def request_cas_response(uri, type, options={})
      log.debug "Requesting CAS response for URI #{uri}"

      uri = URI.parse(uri) unless uri.kind_of? URI
      https = https_connection(uri)
      begin
        raw_res = https.start do |conn|
          conn.get("#{uri.path}?#{uri.query}")
        end
      rescue Errno::ECONNREFUSED => e
        log.error "CAS server did not respond! (#{e.inspect})"
        raise "The CAS authentication server at #{uri} is not responding!"
      end

      # We accept responses of type 422 since RubyCAS-Server generates these
      # in response to requests from the client that are processable but contain
      # invalid CAS data (for example an invalid service ticket).
      if raw_res.kind_of?(Net::HTTPSuccess) || raw_res.code.to_i == 422
        log.debug "CAS server responded with #{raw_res.inspect}:\n#{raw_res.body}"
      else
        log.error "CAS server responded with an error! (#{raw_res.inspect})"
        raise "The CAS authentication server at #{uri} responded with an error (#{raw_res.inspect})!"
      end

      type.new(raw_res.body, @conf_options)
    end

    # Submits some data to the given URI and returns a Net::HTTPResponse.
    def submit_data_to_cas(uri, data)
      uri = URI.parse(uri) unless uri.kind_of? URI
      req = Net::HTTP::Post.new(uri.path)
      req.set_form_data(data, ';')
      https = https_connection(uri)
      https.start {|conn| conn.request(req) }
    end

    def query_to_hash(query)
      CGI.parse(query)
    end

    def hash_to_query(hash)
      pairs = []
      hash.each do |k, vals|
        vals = [vals] unless vals.kind_of? Array
        vals.each {|v| pairs << (v.nil? ? CGI.escape(k) : "#{CGI.escape(k)}=#{CGI.escape(v)}")}
      end
      pairs.join("&")
    end
  end

  class CosignException < Exception
  end

  class Logger < ::Logger
    def initialize(logdev, shift_age = 0, shift_size = 1048576)
      @default_formatter = Formatter.new
      super
    end

    def format_message(severity, datetime, progrname, msg)
      (@formatter || @default_formatter).call(severity, datetime, progname, msg)
    end

    def break
      self << $/
    end

    class Formatter < ::Logger::Formatter
      Format = "[%s#%d] %5s -- %s: %s\n"

      def call(severity, time, progname, msg)
        Format % [format_datetime(time), $$, severity, progname, msg2str(msg)]
      end
    end
  end

  # Wraps a real Logger. If no real Logger is set, then this wrapper
  # will quietly swallow any logging calls.
  class LoggerWrapper
    def initialize(real_logger=nil)
      set_logger(real_logger)
    end
    # Assign the 'real' Logger instance that this dummy instance wraps around.
    def set_real_logger(real_logger)
      @real_logger = real_logger
    end
    # Log using the appropriate method if we have a logger
    # if we dont' have a logger, gracefully ignore.
    def method_missing(name, *args)
      if !@real_logger.nil? && @real_logger.respond_to?(name)
        @real_logger.send(name, *args)
      end
    end
  end

  # Represents a CAS service ticket.
  class ServiceTicket
    attr_reader :ticket, :service, :renew
    attr_accessor :user, :extra_attributes, :pgt_iou, :success, :failure_code, :failure_message

    def initialize(ticket, service, renew = false)
      @ticket = ticket
      @service = service
      @renew = renew
    end

    def is_valid?
      success
    end

    def has_been_validated?
      not user.nil?
    end
  end

  # Represents a CAS proxy ticket.
  class ProxyTicket < ServiceTicket
  end

  class ProxyGrantingTicket
    attr_reader :ticket, :iou

    def initialize(ticket, iou)
      @ticket = ticket
      @iou = iou
    end

    def to_s
      ticket
    end
  end

end