# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "logstash/plugin_mixins/aws_config"
require "logstash/timestamp"
require "time"
require "tmpdir"
require "stud/interval"
require "stud/temporary"

# Stream events from ClougWatch Logs streams.
#
# Primarily designed to pull logs from Lambda's which are logging to
# CloudWatch Logs. Specify a log group, and this plugin will scan
# all log streams in that group, and pull in any new log events.
#
class LogStash::Inputs::CloudWatch_Logs < LogStash::Inputs::Base
  include LogStash::PluginMixins::AwsConfig::V2

  config_name "cloudwatch_logs"

  default :codec, "plain"

  # Log group to pull logs from for this plugin. Will pull in all
  # streams inside of this log group.
  config :log_group, :validate => :string, :required => true

  # Where to write the since database (keeps track of the date
  # the last handled file was added to S3). The default will write
  # sincedb files to some path matching "$HOME/.sincedb*"
  # Should be a path with filename not just a directory.
  config :sincedb_path, :validate => :string, :default => nil

  # Interval to wait between to check the file list again after a run is finished.
  # Value is in seconds.
  config :interval, :validate => :number, :default => 60

  # def register
  public
  def register
    require "digest/md5"
    require "aws-sdk"

    @logger.info("Registering cloudwatch_logs input", :log_group => @log_group)

    Aws::ConfigService::Client.new(aws_options_hash)

    @cloudwatch = Aws::CloudWatchLogs::Client.new(aws_options_hash)
  end #def register

  # def run
  public
  def run(queue)
    while !stop?
      process_group(queue)
      Stud.stoppable_sleep(@interval)
    end
  end # def run

  # def list_new_streams
  public
  def list_new_streams(last_read, token = nil,  objects = [])
    params = {
        :log_group_name => @log_group,
        :order_by => "LastEventTime",
        :descending => true
    }

    if token != nil
      params[:next_token] = token
    end

    streams = @cloudwatch.describe_log_streams(params)
    streams.log_streams.each do |stream|
      if stream.first_event_timestamp > last_read
        objects.unshift(stream)
        @logger.debug("Processing Log Stream #{stream.log_stream_name} which started at #{parse_time(stream.first_event_timestamp)}")
      else
        @logger.debug("Ignoring Log Stream #{stream.log_stream_name} which started at #{parse_time(stream.first_event_timestamp)}")
      end
    end

    if streams.next_token == nil
      @logger.debug("CloudWatch Logs hit end of tokens for streams")
      objects
    else
      @logger.debug("CloudWatch Logs calling list_new_streams again on token", :token => streams.next_token)
      list_new_streams(last_read, streams.next_token, objects)
    end

  end # def list_new_streams

  # def process_log
  private
  def process_log(queue, log, stream)

    @codec.decode(log.message.to_str) do |event|
      event.set("@timestamp", parse_time(log.timestamp))
      event.set("[cloudwatch][ingestion_time]", parse_time(log.ingestion_time))
      event.set("[cloudwatch][log_group]", @log_group)
      event.set("[cloudwatch][log_stream]", stream.log_stream_name)
      decorate(event)

      queue << event
    end
  end
  # def process_log

  # def parse_time
  private
  def parse_time(data)
    LogStash::Timestamp.at(data.to_i / 1000, (data.to_i % 1000) * 1000)
  end # def parse_time

  # def process_group
  public
  def process_group(queue)
    last_read = sincedb.read
    current_window = DateTime.now.strftime('%Q')

    objects = list_new_streams(last_read)

    if last_read < 0
      last_read = 1
    end

    objects.each do |stream|
      if stream.last_ingestion_time && stream.last_ingestion_time > last_read
        process_log_stream(queue, stream, last_read, current_window)
      end
    end

    sincedb.write(current_window)
  end # def process_group

  # def process_log_stream
  private
  def process_log_stream(queue, stream, last_read, current_window, token = nil)
    @logger.debug("CloudWatch Logs processing stream",
                  :log_stream => stream.log_stream_name,
                  :log_group => @log_group,
                  :lastRead => last_read,
                  :currentWindow => current_window,
                  :token => token
    )

    params = {
        :log_group_name => @log_group,
        :log_stream_name => stream.log_stream_name,
        :start_from_head => true
    }

    if token != nil
      params[:next_token] = token
    end

    logs = @cloudwatch.get_log_events(params)

    logs.events.each do |log|
      if log.ingestion_time > last_read
        process_log(queue, log, stream)
      end
    end

    # if there are more pages, continue
    if logs.events.count != 0 && logs.next_forward_token != nil
      process_log_stream(queue, stream, last_read, current_window, logs.next_forward_token)
    end
  end # def process_log_stream

  private
  def sincedb
    @sincedb ||= if @sincedb_path.nil?
                   @logger.info("Using default generated file for the sincedb", :filename => sincedb_file)
                   SinceDB::File.new(sincedb_file)
                 else
                   @logger.info("Using the provided sincedb_path",
                                :sincedb_path => @sincedb_path)
                   SinceDB::File.new(@sincedb_path)
                 end
  end

  private
  def sincedb_file
    File.join(ENV["HOME"], ".sincedb_" + Digest::MD5.hexdigest("#{@log_group}"))
  end

  module SinceDB
    class File
      def initialize(file)
        @sincedb_path = file
      end

      def newer?(date)
        date > read
      end

      def read
        if ::File.exists?(@sincedb_path)
          since = ::File.read(@sincedb_path).chomp.strip.to_i
        else
          since = 1
        end
        return since
      end

      def write(since = nil)
        since = DateTime.now.strftime('%Q') if since.nil?
        ::File.open(@sincedb_path, 'w') { |file| file.write(since.to_s) }
      end
    end
  end
end # class LogStash::Inputs::CloudWatch_Logs
