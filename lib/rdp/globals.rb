
module RDP

  # Header length

  TPKT_HEADER_LENGTH                    = 4
  TPDU_DATA_HEADER_LENGTH               = 3
  TPDU_CONNECTION_REQUEST_HEADER_LENGTH = 7
  TPDU_CONNECTION_CONFIRM_HEADER_LENGTH = 7
  TPDU_DISCONNECT_REQUEST_HEADER_LENGTH = 7

  TPDU_DATA_LENGTH                      = (TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH              )
  TPDU_CONNECTION_REQUEST_LENGTH        = (TPKT_HEADER_LENGTH + TPDU_CONNECTION_REQUEST_HEADER_LENGTH)
  TPDU_CONNECTION_CONFIRM_LENGTH        = (TPKT_HEADER_LENGTH + TPDU_CONNECTION_CONFIRM_HEADER_LENGTH)
  TPDU_DISCONNECT_REQUEST_LENGTH        = (TPKT_HEADER_LENGTH + TPDU_DISCONNECT_REQUEST_HEADER_LENGTH)

  NEG_RSP_LENGTH                        = 8
  NEG_FAILURE_LENGTH                    = 8

  PRECONNECTION_PDU_V1_SIZE             = 16
  PRECONNECTION_PDU_V2_MIN_SIZE         = (PRECONNECTION_PDU_V1_SIZE + 2)


  # X224_TPDU_CONNECTION_REQUEST
  TYPE_RDP_NEG_REQ                      = 0x01 # connection from the client
  # X224_TPDU_CONNECTION_CONFIRM
  TYPE_RDP_NEG_RSP                      = 0x02 # response of the server
  TYPE_RDP_NEG_FAILURE                  = 0x03 # negotiation failure (of security protocol)

  # protocol flags
  RESTRICTED_ADMIN_MODE_REQUIRED        = 0x01
  CORRELATION_INFO_PRESENT              = 0x08

  # security protocols
  PROTOCOL_RDP                          = 0x00000000                                        # standard security
  PROTOCOL_SSL                          = 0x00000001                                        # use TLS
  PROTOCOL_HYBRID                       = 0x00000002                                        #
  PROTOCOL_HYBRID_EXT                   = 0x00000008                                        #
  PROTOCOL_ALL                          = RDP::PROTOCOL_RDP    | RDP::PROTOCOL_SSL        |
      RDP::PROTOCOL_HYBRID | RDP::PROTOCOL_HYBRID_EXT   # can arrive like this

  TYPE_RDP_CORRELATION_INFO             = 0x06 # the type of packet

  #
  EXTENDED_CLIENT_DATA_SUPPORTED        = 0x01 # The server support extended Client Data Blocks in the GCC (conference
  # create request) user data
  DYNVC_GFX_PROTOCOL_SUPPORTED          = 0x02 # The server supports the grapgics pipeline extension protocol
  # (MS-RDPEGFX), section 1, 2 and 3
  NEGRSP_FLAG_RESERVED                  = 0x04 # An unused flag that is reserved for future use.
  RESTRICTED_ADMIN_MODE_SUPPORTED       = 0x08 # Indicates that the server supports credential-less logon over
  # CredSSP (also known as "restricted admin mode") and it is
  # acceptable for the client to send empty credentials in the
  # TSPasswordCreds structure defined in [MS-CSSP] section
  # 2.2.1.2.1.
  NEG_RSP_ALL_FLAGS                     = RDP::EXTENDED_CLIENT_DATA_SUPPORTED | RDP::DYNVC_GFX_PROTOCOL_SUPPORTED |
      RDP::NEGRSP_FLAG_RESERVED | RDP::RESTRICTED_ADMIN_MODE_SUPPORTED


  RDP_PRECONNECTION_PDU_V1              = 0x00000001 #  A version 1 connection PDU
  RDP_PRECONNECTION_PDU_V2              = 0x00000002 #  A version 2 connection PDU


  # Important note: The following values are written in binary at the x.224 specs
  # section 13.1
  X224_TPDU_CONNECTION_REQUEST          = 0xE0 # CR - 11100000 value at the x.224 specs: 1110 xxxx
  X224_TPDU_CONNECTION_CONFIRM          = 0xD0 # CC - 11010000 value at the x.224 specs: 1101 xxxx
  X224_TPDU_DISCONNECT_REQUEST          = 0x80 # DR - 10000000 value at the x.224 specs: 1000 0000
  X224_TPDU_DATA                        = 0xF0 # DT - 11110000 value at the x.224 specs: 1111 000y
  X224_TPDU_ERROR                       = 0x70 # ER - 11100000 value at the x.224 specs: 0111 0000

  X224_STANDARD_REQUEST                 = 0xFF


  # RDP_NEG_FAILURE failureCode(s)
  ERR_SSL_REQUIRED_BY_SERVER                = 0x00000001 # The server requires that the client support Enhanced RDP Security
  # (section 5.4) with either TLS 1.0, 1.1 or 1.2 (section 5.4.5.1)
  # or CredSSP (section 5.4.5.2). If only CredSSP was requested then
  # the server only supports TLS.
  ERR_SSL_NOT_ALLOWED_BY_SERVER             = 0x00000002 # The server is configured to only use Standard RDP Security
  # mechanisms (section 5.3) and does not support any External
  # Security Protocols (section 5.4.5).
  ERR_SSL_CERT_NOT_ON_SERVER                = 0x00000003 # The server does not possess a valid authentication certificate
  # and cannot initialize the External Security Protocol Provider
  # (section 5.4.5).
  ERR_INCONSISTENT_FLAGS                    = 0x00000004 # The list of requested security protocols is not consistent with
  # the current security protocol in effect. This error is only
  # possible when the Direct Approach (sections 5.4.2.2 and 1.3.1.2)
  # is used and an External Security Protocol (section 5.4.5) is
  # already being used.
  ERR_HYBRID_REQUIRED_BY_SERVER             = 0x00000005 # The server requires that the client support Enhanced RDP Security
  # (section 5.4) with CredSSP (section 5.4.5.2).
  ERR_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER = 0x00000006 # The server requires that the client support Enhanced RDP
  # Security (section 5.4) with TLS 1.0, 1.1 or 1.2
  # (section 5.4.5.1) and certificate-based client authentication.

  # Internal usage
  X224_CRQ_SIZE                         = 7
  RDP_NEG_REQ_SIZE                      = 8
  RDP_CORRELATION_INFO_SIZE             = 36
  RDP_COOKIE_MIN_SIZE                   = 15

  def self.x224_tpdu_type
    {
        X224_TPDU_CONNECTION_REQUEST => 'X224_TPDU_CONNECTION_REQUEST',
        X224_TPDU_CONNECTION_CONFIRM => 'X224_TPDU_CONNECTION_CONFIRM',
        X224_TPDU_DISCONNECT_REQUEST => 'X224_TPDU_DISCONNECT_REQUEST',
        X224_TPDU_DATA               => 'X224_TPDU_DATA',
        X224_TPDU_ERROR              => 'X224_TPDU_ERROR',
        X224_STANDARD_REQUEST        => 'X224_STANDARD_REQUEST'
    }
  end

  def self.neg_err_type
    {
        ERR_SSL_REQUIRED_BY_SERVER                => 'SSL_REQUIRED_BY_SERVER',
        ERR_SSL_NOT_ALLOWED_BY_SERVER             => 'SSL_NOT_ALLOWED_BY_SERVER',
        ERR_SSL_CERT_NOT_ON_SERVER                => 'SSL_CERT_NOT_ON_SERVER',
        ERR_INCONSISTENT_FLAGS                    => 'INCONSISTENT_FLAGS',
        ERR_HYBRID_REQUIRED_BY_SERVER             => 'HYBRID_REQUIRED_BY_SERVER',
        ERR_SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER => 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER'
    }
  end

  class RDPException < Exception
  end
end