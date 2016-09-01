
module RDP
  
  class NegFailureHeader
    attr_accessor :type, :flags, :length, :failure_code
    
    def initialize(payload)
      @payload = payload
      parse!(@payload) unless @payload.nil?
    end
    
    def parse!(payload)
      data = payload.unpack('CCvV')
      
      raise RDP::RDPException.new('Invalid type value for RDP_NEG_FAILURE')   unless data[0] == RDP::TYPE_RDP_NEG_FAILURE
      raise RDP::RDPException.new('Invalid flags value for RDP_NEG_FAILURE')  unless data[1] == 0
      raise RDP::RDPException.new('Invalid length value for RDP_NEG_FAILURE') unless data[2] == RDP::NEG_FAILURE_LENGTH
      raise RDP::RDPException.new('Unknown failureCode')                      unless (ERR_SSL_REQUIRED_BY_SERVER..ERR_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER).include? data[3]
      
      @type         = data[0]
      @flags        = data[1]
      @length       = data[2]
      @failure_code = data[3]
    end
    
    # Generating a neg_failure header
    #
    # parameters:
    #    failure_code - The error to return
    #
    # returns:
    #    A raw binary string of the header
    #
    def generate_neg_failure_header(failure_code)
      [
          RDP::TYPE_RDP_NEG_FAILURE,     # type
          0,                             # flags
          RDP::NEG_FAILURE_LENGTH,       # length
          failure_code
      ].pack('CCvV')
    end
    
  end
  
end
