#
# TPDUs are defined in:
#
# http://www.itu.int/rec/T-REC-X.224-199511-I/
# X.224: Information technology - Open Systems Interconnection - Protocol for providing the connection-mode transport service
#
# RDP uses only TPDUs of class 0, the "simple class" defined in section 8 of X.224
#
#
# All the Transport Protocol Data Units (TPDUs) shall contain an integral number of octets. The octets in a TPDU are
# numbered starting from 1 and increasing in the order they are put into an NDSU. The bits in an octet are numbered
# from 1 to 8, where bit 1 is the lowest order bit.
#
# When consecutive octets are used to represent a binary number, the lower octet number has the most significant value.
# NOTES
# 1 The numbering of bits within an octet is a convention local to this Recommendation | International Standard.
# 2 The use of the terms “high order” and “low order” is common to this Recommendation | International Standard and to
#   adjacent layer Standards.
# 3 The use of the above conventions does not affect the order of bit transmission on a serial communications link.
# 4 As described in 6.2.3, both transport entities respect these bit and octet ordering conventions, thus allowing
#   communication to take place.
# 5 In this clause the encoding of TPDUs is represented in the following form:
#   a) octets are shown with the lowest numbered
#      octet to the left; higher numbered octets being further to the r ight;
#    b) within an octet, bits are shown with bit 8 to the left and bit 1 to the right.
#
# TPDUs shall contain, in the following order:
# a) the header, comprising:
#     1) the Length Indicator (LI) field;
#     2) the fixed part;
#     3) the variable part, if present;
#
# b) the data field, if present.
#
#
# The structure is illustrated below:
#
#       TPDU Header
#  ____________________   byte
# |                    |
# |         LI         |   1
# |____________________|
# |                    |
# |        Code        |   2
# |____________________|
# |                    |
# |                    |   3
# |_______DST-REF______|
# |                    |
# |                    |   4
# |____________________|
# |                    |
# |                    |   5
# |_______SRC-REF______|
# |                    |
# |                    |   6
# |____________________|
# |                    |
# |        Class       |   7
# |____________________|
# |         ...        |
#
#
# 13.2.1
# Length indicator field
# The field is contained in the first octet of the TPDUs. The length is indicated by a binary number, with a maximum value
# of 254 (1111 1110). The length indicated shall be the header length in octets including parameters, but excluding the
# length indicator field and user data, if any. The value 255 (1111 1111) is reserved for possible extensions.
#     If the length indicated exceeds or is equal to the size of the NS-user data which is present, this is a protocol error.
#
# 13.2.2
# Fixed part
#
# 13.2.2.1 General
# The fixed part contains frequently occurring parameters including the code of the TPDU. The length and the structure of
# the fixed part are defined by the TPDU code and in certain cases by the protocol class and the formats in use (normal or
#  extended). If any of the parameters of the fixed part have an invalid value, or if the fixed part cannot be contained
#  within the header (as defined by LI), this is a protocol error.
#
#  NOTE – In general, the TPDU code defines the fixed part unambiguously. However, different variants may exist for the
#          same TPDU code (see normal and extended formats).
#
# 13.2.2.2 TPDU code
# This field contains the TPDU code and is contained in octet 2 of the header. It is used to define the structure of the
# remaining header. This field is a full octet except in the following cases:
#     1110 xxxx Connection request
#     1101 xxxx Connection confirm
#     1111 000y Data
#     0101 xxxx Reject
#     0110 xxxx Data acknowledgement
#
# where
#    xxxx (bits 4 to 1) is used to signal the CDT.
#    y (bit 1) is used to signal ROA if the request acknowledgement has been agreed at connection establishment
#    (class 1, 3, 4 only). This bit shall be set to 0 if the request acknowledgement procedure has not been agreed.
#
# Only those codes defined in 13.1 are valid.
#

module RDP
  
  class X224Header
    
    attr_accessor :length, :pdu_type, :variable_part, :variable, :neg_req, :neg_correlation_info
    
    def initialize(payload)
      @payload = payload
      @neg_req = nil
      
      parse! unless @payload.nil?
    end
    
    def parse!
      full_data               = @payload.byteslice(0..6)
      tmp                     = full_data.unpack('C*')
      
      @length                 = tmp[0]
      @pdu_type               = tmp[1]
      @var_length             = 0
      @neg_req_length         = 0
      @neg_correlation_length = 0 # to make sure we have it, for now, there is no use for it
      
      # extract cookie/connection routing
      extract_variable
      
      # extract rdpNegReq info
      extract_negotiation_request
      
      # extract rdpCorrelationInfo
      extract_correlation_info
    end
        
    # The following method generate an x.224 CCF header in bytes
    #
    # Parameters:
    #  code    - The TPDU code to use
    #  length  - The Length indicator field
    #  src_ref - The source reference (default 0x1234)
    #  dst_ref - The destination reference (default 0)
    #  kclass  - The class to use (default 0)
    #
    # Returns:
    #   A raw binary string made of x.224 CCF header
    #
    def generate_x224Ccf_header(code, length, src_ref=0x1234, dst_ref=0, kclass=0)
      base = [
          length,
          code
      ]
      
      # data
      if code == RDP::X224_TPDU_DATA
        base << RDP::X224_TPDU_DISCONNECT_REQUEST
        return base.pack('CCC')
      end
      
      # non data
      base << dst_ref     # DST-REF
      base << src_ref     # SRC-REF
      base << kclass      # Class 0
    
      base.pack('CCnnC')
    end
    
    def extract_variable
      
      # routingToken (variable): An optional and variable-length routing
      # token (used for load balancing) terminated by a 0x0D0A two-byte
      # sequence: (check [MSFT-SDLBTS] for details!)
      # Cookie:[space]msts=[ip address].[port].[reserved][\x0D\x0A]
      #
      #
      # cookie (variable): An optional and variable-length ANSI character
      # string terminated by a 0x0D0A two-byte sequence:
      # Cookie:[space]mstshash=[ANSISTRING][\x0D\x0A]
      
      
      # is there at least a length for the minimal cookie part?
      # *NOTE*: it does not indicate anything yet, just a possibility
      if @length >= RDP::RDP_COOKIE_MIN_SIZE
        
        @variable_part = @payload.byteslice(RDP::X224_CRQ_SIZE..@payload.index("\r\n") + 1)
        
        raise RDP::RDPException.new('Invalid variable content') if  @variable_part.empty?
        
        # set the variable size
        @var_length = @variable_part.length
        
        # remove CR+LF <- it's just an indicator, not part of the value
        @variable = @variable_part.chomp
      end
    end
    
    def variable_as_ip
      if variable_type == :routingToken
        @variable.to_s =~ /msts=(\d*)\.(\d*)\./
        iphex = sprintf( "%8X", $1 )
        porthex = sprintf( "%4X", $2 )
        iphex =~ /(..)(..)(..)(..)/s
        "#{$4.hex}.#{$3.hex}.#{$2.hex}.#{$1.hex}"
      else
        false
      end
    end
    
    def extract_negotiation_request
      
      # do we have (or think we have) RDP NEGOTIATION header?
      if @length >= @var_length + RDP::RDP_NEG_REQ_SIZE
        data = @payload.byteslice((RDP::X224_CRQ_SIZE + @var_length)..(RDP::X224_CRQ_SIZE + @var_length) + RDP::RDP_NEG_REQ_SIZE)
        parsing = data.unpack('CCvV')
        
        # puts "parsing: #{parsing}"
        
        raise RDP::RDPException.new('Invalid negotiation length')              unless                                      parsing[2] == 0x0008 # it must be always equal to 8
        raise RDP::RDPException.new('Invalid negotiation request type')        unless                                      parsing[0] == RDP::TYPE_RDP_NEG_REQ
        raise RDP::RDPException.new('Invalid negotiation requested protocols')     if                                      parsing[3]  > RDP::PROTOCOL_ALL
        
        raise RDP::RDPException.new('Invalid negotiation flag')                unless [0,   # documented only at the example level :'(
                                                                               RDP::RESTRICTED_ADMIN_MODE_REQUIRED,
                                                                               RDP::CORRELATION_INFO_PRESENT].        include?    parsing[1]
        
        # know to take in consideration the position of neg req
        @neg_req_length = RDP::RDP_NEG_REQ_SIZE
        @neg_req = NegReqHeader.new(parsing)
        
        # puts @neg_req.inspect
      
      end
    end
    
    def extract_correlation_info
      if @length >= @var_length + @neg_req_length + RDP::RDP_CORRELATION_INFO_SIZE
        data = @payload.byteslice((RDP::X224_CRQ_SIZE + @var_length)..(RDP::X224_CRQ_SIZE + @var_length) + RDP::RDP_CORRELATION_INFO_SIZE)

        # pages 37-38 [MS-RDPBCGR]
        # type (1 byte): An 8-bit, unsigned integer that indicates the packet type. This field MUST be set to
        # 0x06 (TYPE_RDP_CORRELATION_INFO).
        #     flags (1 byte): An 8-bit, unsigned integer that contains protocol flags. There are currently no defined
        # flags, so this field MUST be set to 0x00.
        #     length (2 bytes): A 16-bit, unsigned integer that specifies the packet size. This field MUST be set to
        # 0x0024 (36 bytes).
        # correlationId (16 bytes): An array of sixteen 8-bit, unsigned integers that specifies a unique
        # identifier to associate with the connection. The first byte in the array SHOULD NOT have a value of
        # 0x00 or 0xF4 and the value 0x0D SHOULD NOT be contained in any of the bytes.
        #     reserved (16 bytes): An array of sixteen 8-bit, unsigned integers reserved for future use. All sixteen
        #     integers within this array MUST be set to zero.
        parsing = data.unpack('CCvC16C16')
        
        raise RDP::RDPException.new('Invalid correlation header content') unless parsing.count == 7
        
        raise RDP::RDPException.new('Invalid correlation version') unless parsing[0] == RDP::TYPE_RDP_CORRELATION_INFO
        raise RDP::RDPException.new('Invalid correlation flags')   unless parsing[1] == 0x00
        raise RDP::RDPException.new('Invalid correlation length')  unless parsing[2] == 0x0024
        
        # Important!
        # DO NOT VALIDATE CorrelationId and Reserved in this location, they are they are not yet fully parsed here!
        # so the parsing and the validated happens only at NegCorrelationInfoHeader class
        # Important!
        
        # puts parsing.inspect
        @neg_correlation_length = RDP::RDP_CORRELATION_INFO_SIZE
        @neg_correlation_info   = RDP::NegCorrelationInfoHeader.new(parsing)
        
      end
    end
    
    def variable_type
      # The routingToken can be converted back to IP address by using the following logic
      # "msts=420247818.15629.0000" =~ /^msts=(\d*)\.(\d*)\./
      # iphex = sprintf( "%8X", $1 )
      # porthex = sprintf( "%4X", $2 )
      # iphex =~ /(..)(..)(..)(..)/s
      # "#{$4.hex}.#{$3.hex}.#{$2.hex}.#{$1.hex}"
      
      return :no_var       if @variable.nil?
      return :cookie if @variable.start_with? 'Cookie: mstshash='
      return :routingToken       if @variable.start_with? 'Cookie: msts='
      
      :type_unknown
    end
    
    def cookie?
      variable_type == :cookie
    end
    
    def routing_token?
      variable_type == :routingToken
    end
  
  end

end