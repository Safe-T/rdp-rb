module RDP
  class NegRspHeader
    VALID_PROTOCOLS = [
      RDP::PROTOCOL_RDP,
      RDP::PROTOCOL_SSL,
      RDP::PROTOCOL_HYBRID,
      RDP::PROTOCOL_HYBRID_EXT
    ].freeze
    attr_accessor :flags, :protocol

    def initialize(settings = {})
      @flags    = settings[:flags]    || nil
      @protocol = settings[:protocol] || nil
    end

    # create a binary packet made out of the data packet
    def generate_packet
      raise RDP::RDPException, 'flags and protocol cannot be nil for generate_packet' if @flags.nil? || @protocol.nil?

      [
        RDP::TYPE_RDP_NEG_RSP,   # The type of packet
        @flags,                  # flags
        RDP::NEG_RSP_LENGTH,     # length -> must be always be 0x0008
        @protocol                # the selected protocol to use
      ].pack('CCnN')
    end

    # parse a given data back
    def parse(payload)
      if payload.is_a? String
        parse_string(payload)
      elsif payload.is_a? Array
        parse_array(payload)
      else
        raise RDP::RDPException, 'Unsupported payload type'
      end
    end

    def parse_string(payload)
      data = payload.unpack('CCvV')

      raise RDP::RDPException, 'Invalid data for type' unless data[0] == RDP::TYPE_RDP_NEG_RSP
      # length (2 bytes): A 16-bit, unsigned integer that specifies the
      # packet size. This field MUST be set to 0x0008 (8 bytes)
      raise RDP::RDPException, 'Invalid length size'   unless data[2] == RDP::NEG_RSP_LENGTH

      @flags = data[1]
      raise RDP::RDPException, 'Invalid flags' unless (1..RDP::NEG_RSP_ALL_FLAGS).include?(@flags)

      @protocol = data[3]
      raise RDP::RDPException, 'Unsupported security protocol' unless VALID_PROTOCOLS.include? @protocol
    end

    def parse_array(payload)
      raise RDP::RDPException, 'Invalid payload array size' if payload.length != 4
      raise RDP::RDPException, 'Invalid data for type'      unless payload[0] == RDP::TYPE_RDP_NEG_RSP
      # length (2 bytes): A 16-bit, unsigned integer that specifies the
      # packet size. This field MUST be set to 0x0008 (8 bytes)
      raise RDP::RDPException, 'Invalid length size'        unless payload[2] == RDP::NEG_RSP_LENGTH

      @flags = payload[1]
      raise RDP::RDPException, 'Invalid flags' unless (1..RDP::NEG_RSP_ALL_FLAGS).include?(@flags)

      @protocol = payload[3]
      raise RDP::RDPException, 'Unsupported security protocol' unless VALID_PROTOCOLS.include? @protocol
    end

  end
end
