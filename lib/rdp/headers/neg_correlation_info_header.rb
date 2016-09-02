module RDP

  class NegCorrelationInfoHeader
    attr_accessor :type, :flags, :length, :correlation_id, :reserved

    def initialize(payload)
      @payload = payload

      @type   = @payload[0]
      @flags  = @payload[1]
      @length = @payload[2]

      parse!
    end

    # parse correlationId and reserved
    # if something is wrong, it will raise an exception of RDP::RDPException
    def parse!
      @correnlation_id = payload[3...20] # extract the information
      @reserved        = payload[20..36] # extract the information

      raise RDP::RDPException.new('Invalid neg_correlation_info correlation_id') unless @correnlation_id.select {
          |x| x != 0 && x != 0xF4}.count == 0

      raise RDP::RDPException.new('Invalid neg_correlation_info reserved') unless @reserved.select{
          |x| x != 0}.count == 0

    end

  end

end
