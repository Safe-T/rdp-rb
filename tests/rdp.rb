require 'socket'
require_relative '../lib/rdp'

def first_response(selected, flags = 0, error = false)
  # calculating the entire size of the entire packet
  length = RDP::TPDU_CONNECTION_CONFIRM_LENGTH

  tpkt = RDP::TPKTHeaderParser.new(nil)
  x224 = RDP::X224Header.new(nil)
  req  = if error
           length += RDP::NEG_FAILURE_LENGTH
           RDP::NegFailureHeader.new(nil)
         else
           length += RDP::NEG_RSP_LENGTH
           RDP::NegRspHeader.new(flags: flags, protocol: selected)
         end

  x224_header = x224.generate_x224Ccf_header(RDP::X224_TPDU_CONNECTION_CONFIRM, length - 5)

  tpkt.generate_packet(length) + x224_header +
    (req.is_a?(RDP::NegFailureHeader) ? req.generate_neg_failure_header(selected) : req.generate_packet)
end

def listen
  begin
    s = TCPServer.new(3389)
    client = s.accept
    rdp = RDP::NegReqAction.new(client)
    rdp.read
    puts "Got From Client:\r\n #{rdp.explain}"

    puts 'Going to send first response:'
    client.write(first_response(RDP::ERR_SSL_NOT_ALLOWED_BY_SERVER, 0, true))
    puts 'sent it'

    rdp.read
    puts "Got From Client:\r\n #{rdp.explain}"
    client.close
    s.close
  rescue Exception => e
    puts "Error: #{e.message}\nBacktrace: #{e.backtrace}"
  ensure
    s.close
  end
end

listen
