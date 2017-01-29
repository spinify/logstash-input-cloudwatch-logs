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
  config :sincedb_path, :validate => :string, :default => nil, :obsolete => "Since DB path is always automatically computed"

  # Interval to wait between to check the file list again after a run is finished.
  # Value is in seconds.
  config :interval, :validate => :number, :default => 60

  # Specify the maximum CloudWatch history in days to read back.
  # Doesnot override sincedb, so once you've started capturing logs, if
  # you start again, it will still ensure there are no gaps.
  config :max_history, :validate => :number, :default => nil

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
      if( @log_group.end_with?('*') )
        list_groups(@log_group.chomp).each do |group|
          process_group(queue, group)
        end
      else
        process_group(queue, @log_group)
      end
      Stud.stoppable_sleep(@interval)
    end
  end # def run


  # def list_groups
  public
  def list_groups(prefix = "", token = nil, groups = [])
    params = {
      log_group_name_prefix: prefix
    }
    if token != nil
      params[:next_token] = token
    end

    groups_descriptor = @cloudwatch.describe_log_groups(params)
    groups.concat(groups_descriptor.log_groups.map { |g| g.log_group_name })

    if groups_descriptor.next_token == nil
      groups
    else
      list_groups(prefix, groups_descriptor.next_token, groups)
    end
  end # def list_groups

  # def list_new_streams
  public
  def list_new_streams(group, last_read, token = nil,  objects = [])
    params = {
        :log_group_name => group,
        :order_by => "LastEventTime",
        :descending => true
    }

    if token != nil
      params[:next_token] = token
    end

    streams = @cloudwatch.describe_log_streams(params)
    streams.log_streams.each do |stream|
      if stream.first_event_timestamp > last_read
        @logger.debug("Processing Log Stream #{stream.log_stream_name} which started at #{parse_time(stream.first_event_timestamp)}")
        objects.unshift(stream)
      else
        @logger.debug("Ignoring Log Stream #{stream.log_stream_name} which started at #{parse_time(stream.first_event_timestamp)}")
        break
      end
    end

    if streams.next_token == nil
      @logger.debug("CloudWatch Logs hit end of tokens for streams")
      objects
    else
      @logger.debug("CloudWatch Logs calling list_new_streams again on token", :token => streams.next_token)
      list_new_streams(group, last_read, streams.next_token, objects)
    end

  end # def list_new_streams

  # def process_log
  private
  def process_log(queue, group, log, stream)

    @codec.decode(log.message.to_str) do |event|
      event.set("@timestamp", parse_time(log.timestamp))
      event.set("[cloudwatch][ingestion_time]", parse_time(log.ingestion_time))
      event.set("[cloudwatch][log_group]", group)
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
  def process_group(queue, group)
    last_read = sincedb.read
    current_window = DateTime.now.strftime('%Q')

    objects = list_new_streams(group, last_read)

    if last_read < 0
      last_read = epoch
    end

    objects.each do |stream|
      if stream.last_ingestion_time && stream.last_ingestion_time > last_read
        process_log_stream(queue, group, stream, last_read, current_window)
      end
    end

    sincedb.write(current_window)
  end # def process_group

  # def process_log_stream
  private
  def process_log_stream(queue, group, stream, last_read, current_window, token = nil)
    @logger.debug("CloudWatch Logs processing stream",
                  :log_stream => stream.log_stream_name,
                  :log_group => group,
                  :lastRead => last_read,
                  :currentWindow => current_window,
                  :token => token
    )

    params = {
        :log_group_name => group,
        :log_stream_name => stream.log_stream_name,
        :start_from_head => true
    }

    if token != nil
      params[:next_token] = token
    end

    logs = @cloudwatch.get_log_events(params)

    logs.events.each do |log|
      if log.ingestion_time > last_read
        process_log(queue, group, log, stream)
      end
    end

    # if there are more pages, continue
    if logs.events.count != 0 && logs.next_forward_token != nil
      process_log_stream(queue, group, stream, last_read, current_window, logs.next_forward_token)
    end
  end # def process_log_stream

  private
  def sincedb(group)
    @sincedb ||= {}
    @sincedb[group] ||= SinceDB::File.new(sincedb_file(group), epoch)
  end

  private
  def sincedb_file(group)
    File.join(ENV["HOME"], ".sincedb_" + Digest::MD5.hexdigest("#{group}"))
  end

  # Time to start from
  def epoch
    if @max_history
      DateTime.now.strftime('%Q').to_i - @max_history.to_i * 86400000 # Milliseconds per day
    else
      1 # UNIX Epoch
    end
  end

  module SinceDB
    class File
      def initialize(file, epoch)
        @sincedb_path = file
        @epoch = epoch
      end

      def newer?(date)
        date > read
      end

      def read
        if ::File.exists?(@sincedb_path)
          since = ::File.read(@sincedb_path).chomp.strip.to_i
        else
          since = @epoch
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
