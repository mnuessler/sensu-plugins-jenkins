#! /usr/bin/env ruby
#
#   jenkins-metrics
#
# DESCRIPTION:
#   This plugin extracts the metrics from a Jenkins Master with Metrics plugin installed
#   Anonymous user must have Metrics permissions.
#
# OUTPUT:
#    metric data
#
# PLATFORMS:
#   Linux
#
# DEPENDENCIES:
#   gem: sensu-plugin
#   gem: rest-client
#   gem: socket
#   gem: json
#   gem: openssl
#
# USAGE:
#   #YELLOW
#
# NOTES:
#
# LICENSE:
#   Copyright 2015, Cornel Foltea (cornel.foltea@gmail.com)
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'sensu-plugin/metric/cli'
require 'rest-client'
require 'socket'
require 'json'
require 'openssl'

#
# Jenkins Metrics
#
class JenkinsMetrics < Sensu::Plugin::Metric::CLI::Graphite
  SKIP_ROOT_KEYS = %w[version].freeze

  option :scheme,
         description: 'Metric naming scheme',
         short: '-s SCHEME',
         long: '--scheme SCHEME',
         default: "#{Socket.gethostname}.jenkins"

  option :server,
         description: 'Jenkins Host',
         short: '-S SERVER',
         long: '--server SERVER',
         default: 'localhost'

  option :port,
         description: 'Jenkins Port',
         short: '-p PORT',
         long: '--port PORT',
         proc: proc(&:to_i)

  option :uri,
         description: 'Jenkins Metrics URI',
         short: '-u URI',
         long: '--uri URI',
         default: '/metrics/currentUser/metrics'

  option :https,
         short: '-h',
         long: '--https',
         boolean: true,
         description: 'Enabling https connections',
         default: false

  option :insecure,
         short: '-k',
         long: '--insecure',
         boolean: true,
         description: 'Perform "insecure" SSL connections and transfers.',
         default: false

  option :timeout,
         short: '-t SECONDS',
         long: '--timeout SECONDS',
         description: 'Timeout for REST request',
         proc: proc(&:to_i),
         default: 10

  option :report_request_duration,
         long: '--[no-]report-request-duration',
         boolean: true,
         description: 'Report the duration of the REST request',
         default: true

  option :ssl_ca_cert,
         long: '--ssl_ca_cert CA_CERT',
         description: 'The path to the TLS CA certificate file'

  option :ssl_client_cert,
         long: '--ssl_client_cert CLIENT_CERT',
         description: 'The path to the TLS client certificate file'

  option :ssl_client_key,
         long: '--ssl_client_key CLIENT_KEY',
         description: 'The path to the TLS client key file'

  option :ssl_client_key_pass,
         long: '--ssl_client_key_pass CLIENT_KEY_PASSWORD',
         description: 'The password for the TLS client key'

  def report_request_duration
    return unless config[:report_request_duration]
    @stop ||= DateTime.now
    ms = ((@stop - @start) * 1000 * 24 * 60 * 60).to_i
    output("#{config[:scheme]}.request.duration", ms)
  end

  def run
    @start = DateTime.now
    @stop = nil
    begin
      scheme ||= config[:https] ? 'https' : 'http'
      # port ||= config[:port] ? default_port
      testurl = "#{scheme}://#{config[:server]}:#{config[:port]}#{config[:uri]}"

      r = if config[:https] && config[:insecure]
            RestClient::Resource.new(testurl, timeout: config[:timeout], verify_ssl: false).get
          elsif config[:https]
            if config[:ssl_client_cert]
              client_cert = OpenSSL::X509::Certificate.new(File.read(config[:ssl_client_cert]))
              client_key = OpenSSL::PKey::RSA.new(File.read(config[:ssl_client_key]), config[:ssl_client_key_pass])
              ca_file = config[:ssl_ca_cert]
              verify_ssl = if config[:insecure]
                             OpenSSL::SSL::VERIFY_NONE
                           else
                             OpenSSL::SSL::VERIFY_PEER
                           end
              RestClient::Resource.new(
                testurl,
                timeout: config[:timeout],
                ssl_client_cert: client_cert,
                ssl_client_key: client_key,
                ssl_ca_file: ca_file,
                verify_ssl: verify_ssl
              ).get
            else
              RestClient::Resource.new(testurl, timeout: config[:timeout], verify_ssl: true).get
            end
          else
            RestClient::Resource.new(testurl, timeout: config[:timeout]).get
          end

      @stop = DateTime.now
      all_metrics = JSON.parse(r)
      metric_groups = all_metrics.keys - SKIP_ROOT_KEYS
      metric_groups.each do |metric_groups_key|
        all_metrics[metric_groups_key].each do |metric_key, metric_value|
          metric_value.each do |metric_hash_key, metric_hash_value|
            output([config[:scheme], metric_groups_key, metric_key, metric_hash_key].join('.'), metric_hash_value) \
              if metric_hash_value.is_a?(Numeric) && (metric_hash_key == 'count' || metric_hash_key == 'value')
          end
        end
      end
      ok
    rescue Errno::ECONNREFUSED
      STDERR.write "Jenkins is not responding\n"
      critical
    rescue RestClient::RequestTimeout
      STDERR.write "Jenkins connection timed out\n"
      critical
    ensure
      report_request_duration
    end
    ok
  end
end
