#
# TPKTs are defined in:
#
#  http://tools.ietf.org/html/rfc1006/
#  RFC 1006 - ISO Transport Service on top of the TCP
#
#  http://www.itu.int/rec/T-REC-T.123/
#  ITU-T T.123 (01/2007) - Network-specific data protocol stacks for multimedia conferencing
#
#            TPKT Header
#   ____________________   byte
#  |                    |
#  |     3 (version)    |   1
#  |____________________|
#  |                    |
#  |      Reserved      |   2
#  |____________________|
#  |                    |
#  |    Length (MSB)    |   3
#  |____________________|
#  |                    |
#  |    Length (LSB)    |   4
#  |____________________|
#  |                    |
#  |     X.224 TPDU     |   5 - ?
#          ....
#
#  A TPKT header is of fixed length 4, and the following X.224 TPDU is at least three bytes long.
#  Therefore, the minimum TPKT length is 7, and the maximum TPKT length is 65535. Because the TPKT
#  length includes the TPKT header (4 bytes), the maximum X.224 TPDU length is 65531.
#

module RDP
  class TPKTHeaderParser
    attr_accessor :version, :flags, :data

    def initialize(payload)
      @payload = payload

      parse! unless @payload.nil?
    end

    def parse!
      tmp = @payload.unpack('CCn')

      @version = tmp[0]
      @flags   = tmp[1]
      @data    = tmp[2]

    end

    # Create a full TPKT header including the data o send
    #
    # Parameters:
    #   length - The header + data length
    #
    # Returns:
    #  A raw binary string with the entire header and data to send.
    #
    def generate_packet(length)
      [
          3,       # version
          0,       # reserved
          length#,  # big endian
      ].pack('CCn')
    end

  end
end