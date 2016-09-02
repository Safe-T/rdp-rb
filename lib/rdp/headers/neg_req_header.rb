module RDP
  class NegReqHeader
    attr_accessor :type, :flags, :length, :requested_protocol

    def initialize(data)
      @type               = data[0]
      @flags              = data[1]
      @length             = data[2]
      @requested_protocol = data[3]
    end

    def proto_s
      str = {
          RDP::PROTOCOL_RDP        => 'RDP',
          RDP::PROTOCOL_SSL        => 'SSL/TLS',
          RDP::PROTOCOL_HYBRID     => 'HYBRID',
          RDP::PROTOCOL_HYBRID_EXT => 'HYBRID Extended',
      }

      result = []
      result << str[RDP::PROTOCOL_RDP]        if @requested_protocol & RDP::PROTOCOL_RDP        == RDP::PROTOCOL_RDP
      result << str[RDP::PROTOCOL_SSL]        if @requested_protocol & RDP::PROTOCOL_SSL        == RDP::PROTOCOL_SSL
      result << str[RDP::PROTOCOL_HYBRID]     if @requested_protocol & RDP::PROTOCOL_HYBRID     == RDP::PROTOCOL_HYBRID
      result << str[RDP::PROTOCOL_HYBRID_EXT] if @requested_protocol & RDP::PROTOCOL_HYBRID_EXT == RDP::PROTOCOL_HYBRID_EXT

      result.join(', ')
    end

  end

end