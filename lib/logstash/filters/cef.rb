# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::CEF < LogStash::Filters::Base
  config_name "cef"

  # set the status to experimental/beta/stable
  milestone 1

  # The field to search for CEF data
  config :ceffield, :validate => :string, :default => "message"

  public
  def register
    # Nothing
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    parse_cef(event)
    filter_matched(event)
  end # def filter

  private
  def parse_cef(event)
    # Now, break out the rest of the headers
    # We may have the following logs:
    #  Mar  2 23:08:28 centos whatever: CEF:0|... <- If added correctly to syslog
    #  CEF:0|.... <- If it coming bare (network or file)
    #  Mar  2 23:08:28 centos CEF: 0| <- if we had the CEF forwarded to syslog it may break
    unless event[@ceffield].nil?
      headers = event[@ceffield].match(/.*?CEF:\s?(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^\|\\]*(?:\\.[^\|\\]*)*)\|([^|]*)\|(.*)/).to_a
      event['deviceVendor'] = headers[2]
      event['deviceProduct'] = headers[3]
      event['deviceVersion'] = headers[4]
      event['deviceEventClassId'] = headers[5]
      event['name'] = headers[6]
      event['severity'] = headers[7]
      # Now, try to break out the Extension Dictionary
      unless headers[8].nil?
        ext = headers[8].scan(/(?:_+)?([\w.:\[\]]+)=(.*?(?=(?:\s[\w.:\[\]]+=|$)))/).to_a
        for elem in ext
           event[elem[0]]=elem[1]
        end
      end
    end
  end # def parse_cef
end # class LogStash::Filters::CEF
