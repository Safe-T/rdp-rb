
require 'socket'
require 'openssl'

require_relative 'rdp/version'


# make sure it's always before anything else
require_relative 'rdp/globals'

require_relative 'rdp/negotiation/rdp_negotition'
require_relative 'rdp/headers/tpkt'
require_relative 'rdp/headers/x224'
require_relative 'rdp/headers/neg_req_header'
require_relative 'rdp/headers/neg_correlation_info_header'
require_relative 'rdp/headers/neg_rsp'
require_relative 'rdp/headers/neg_failure'


