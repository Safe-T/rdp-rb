# Connection Sequence: https://msdn.microsoft.com/en-us/library/cc240452.aspx
# A graph:
#
#                                      Connection Sequence
#     client                                                                    server
#        |                                                                         |
#        |-----------------------X.224 Connection Request PDU--------------------->|
#        |<----------------------X.224 Connection Confirm PDU----------------------|
#        |-------MCS Connect-Initial PDU with GCC Conference Create Request------->|
#        |<-----MCS Connect-Response PDU with GCC Conference Create Response-------|
#        |------------------------MCS Erect Domain Request PDU-------------------->|
#        |------------------------MCS Attach User Request PDU--------------------->|
#        |<-----------------------MCS Attach User Confirm PDU----------------------|
#        |------------------------MCS Channel Join Request PDU-------------------->|
#        |<-----------------------MCS Channel Join Confirm PDU---------------------|
#        |----------------------------Security Exchange PDU----------------------->|
#        |-------------------------------Client Info PDU-------------------------->|
#        |<---------------------License Error PDU - Valid Client-------------------|
#        |<-----------------------------Demand Active PDU--------------------------|
#        |------------------------------Confirm Active PDU------------------------>|
#        |-------------------------------Synchronize PDU-------------------------->|
#        |---------------------------Control PDU - Cooperate---------------------->|
#        |------------------------Control PDU - Request Control------------------->|
#        |--------------------------Persistent Key List PDU(s)-------------------->|
#        |--------------------------------Font List PDU--------------------------->|
#        |<------------------------------Synchronize PDU---------------------------|
#        |<--------------------------Control PDU - Cooperate-----------------------|
#        |<-----------------------Control PDU - Granted Control--------------------|
#        |<-------------------------------Font Map PDU-----------------------------|
#

#
#  Connection Sequence
#
#  1.	Connection Initiation: The client initiates the connection by sending the server a
#  	Class 0 X.224 Connection Request PDU (section 2.2.1.1). The server responds with a
#  	Class 0 X.224 Connection Confirm PDU (section 2.2.1.2). From this point, all subsequent
#  	data sent between client and server is wrapped in an X.224 Data Protocol Data Unit (PDU).
#
#  2.	Basic Settings Exchange: Basic settings are exchanged between the client and server by
#  	using the MCS Connect Initial PDU (section 2.2.1.3) and MCS Connect Response PDU (section 2.2.1.4).
#  	The Connect Initial PDU contains a Generic Conference Control (GCC) Conference Create Request,
#  	while the Connect Response PDU contains a GCC Conference Create Response. These two GCC packets
#  	contain concatenated blocks of settings data (such as core data, security data, and network data)
#  	which are read by client and server.
#
#  3.	Channel Connection: The client sends an MCS Erect Domain Request PDU (section 2.2.1.5),
#  	followed by an MCS Attach User Request PDU (section 2.2.1.6) to attach the primary user identity
#  	to the MCS domain. The server responds with an MCS Attach User Confirm PDU (section 2.2.1.7)
#  	containing the User Channel ID. The client then proceeds to join the user channel, the
#  	input/output (I/O) channel, and all of the static virtual channels (the I/O and static virtual
#  	channel IDs are obtained from the data embedded in the GCC packets) by using multiple MCS Channel
#  	Join Request PDUs (section 2.2.1.8). The server confirms each channel with an MCS Channel Join
#  	Confirm PDU (section 2.2.1.9). (The client only sends a Channel Join Request after it has received
#  	the Channel Join Confirm for the previously sent request.)
#
#  	From this point, all subsequent data sent from the client to the server is wrapped in an MCS Send
#  	Data Request PDU, while data sent from the server to the client is wrapped in an MCS Send Data
#  	Indication PDU. This is in addition to the data being wrapped by an X.224 Data PDU.
#
#  4.	RDP Security Commencement: If Standard RDP Security mechanisms (section 5.3) are being employed and
#  	encryption is in force (this is determined by examining the data embedded in the GCC Conference Create
#  	Response packet) then the client sends a Security Exchange PDU (section 2.2.1.10) containing an encrypted
#  	32-byte random number to the server. This random number is encrypted with the public key of the server
#  	as described in section 5.3.4.1 (the server's public key, as well as a 32-byte server-generated random
#  	number, are both obtained from the data embedded in the GCC Conference Create Response packet). The client
#  	and server then utilize the two 32-byte random numbers to generate session keys which are used to encrypt
#  	and validate the integrity of subsequent RDP traffic.
#
#  	From this point, all subsequent RDP traffic can be encrypted and a security header is included with the
#  	data if encryption is in force. (The Client Info PDU (section 2.2.1.11) and licensing PDUs ([MS-RDPELE]
#  	section 2.2.2) are an exception in that they always have a security header). The Security Header follows
#  	the X.224 and MCS Headers and indicates whether the attached data is encrypted. Even if encryption is in
#  	force, server-to-client traffic may not always be encrypted, while client-to-server traffic must always be
#  	encrypted (encryption of licensing PDUs is optional, however).
#
#  5.	Secure Settings Exchange: Secure client data (such as the username, password, and auto-reconnect cookie)
#  	is sent to the server by using the Client Info PDU (section 2.2.1.11).
#
#  6.	Optional Connect-Time Auto-Detection: During the optional connect-time auto-detect phase the goal is to
#  	determine characteristics of the network, such as the round-trip latency time and the bandwidth of the link
#  	between the server and client. This is accomplished by exchanging a collection of PDUs (specified in section 2.2.1.4)
#  	over a predetermined period of time with enough data to ensure that the results are statistically relevant.
#
#  7.	Licensing: The goal of the licensing exchange is to transfer a license from the server to the client.
#  	The client stores this license and on subsequent connections sends the license to the server for validation.
#  	However, in some situations the client may not be issued a license to store. In effect, the packets exchanged
#  	during this phase of the protocol depend on the licensing mechanisms employed by the server. Within the context
#  	of this document, it is assumed that the client will not be issued a license to store. For details regarding
#  	more advanced licensing scenarios that take place during the Licensing Phase, see [MS-RDPELE] section 1.3.
#
#  8.	Optional Multitransport Bootstrapping: After the connection has been secured and the Licensing Phase has run
#  	to completion, the server can choose to initiate multitransport connections ([MS-RDPEMT] section 1.3).
#  	The Initiate Multitransport Request PDU (section 2.2.15.1) is sent by the server to the client and results
#  	in the out-of-band creation of a multitransport connection using messages from the RDP-UDP, TLS, DTLS, and
#  	multitransport protocols ([MS-RDPEMT] section 1.3.1).
#
#  9.	Capabilities Exchange: The server sends the set of capabilities it supports to the client in a Demand Active PDU
#  	(section 2.2.1.13.1). The client responds with its capabilities by sending a Confirm Active PDU (section 2.2.1.13.2).
#
#  10.	Connection Finalization: The client and server exchange PDUs to finalize the connection details. The client-to-server
#  	PDUs sent during this phase have no dependencies on any of the server-to-client PDUs; they may be sent as a single batch,
#  	provided that sequencing is maintained.
#
#  	- The Client Synchronize PDU (section 2.2.1.14) is sent after transmitting the Confirm Active PDU.
#  	- The Client Control (Cooperate) PDU (section 2.2.1.15) is sent after transmitting the Client Synchronize PDU.
#  	- The Client Control (Request Control) PDU (section 2.2.1.16) is sent after transmitting the Client Control (Cooperate) PDU.
#  	- The optional Persistent Key List PDUs (section 2.2.1.17) are sent after transmitting the Client Control (Request Control) PDU.
#  	- The Font List PDU (section 2.2.1.18) is sent after transmitting the Persistent Key List PDUs or, if the Persistent Key List
#  	  PDUs were not sent, it is sent after transmitting the Client Control (Request Control) PDU (section 2.2.1.16).
#
# 	The server-to-client PDUs sent during the Connection Finalization Phase have dependencies on the client-to-server PDUs.
#
# 	- The optional Monitor Layout PDU (section 2.2.12.1) has no dependency on any client-to-server PDUs and is sent after the Demand Active PDU.
# 	- The Server Synchronize PDU (section 2.2.1.19) is sent in response to the Confirm Active PDU.
# 	- The Server Control (Cooperate) PDU (section 2.2.1.20) is sent after transmitting the Server Synchronize PDU.
# 	- The Server Control (Granted Control) PDU (section 2.2.1.21) is sent in response to the Client Control (Request Control) PDU.
# 	- The Font Map PDU (section 2.2.1.22) is sent in response to the Font List PDU.
#
# 	Once the client has sent the Confirm Active PDU, it can start sending mouse and keyboard input to the server, and upon receipt
# 	of the Font List PDU the server can start sending graphics output to the client.
#
# 	Besides input and graphics data, other data that can be exchanged between client and server after the connection has been
# 	finalized includes connection management information and virtual channel messages (exchanged between client-side plug-ins
# 	and server-side applications).
#

module RDP

  class NegReqAction

    def initialize(socket)
      @socket = socket
    end

    def read_tpkt

      payload      = @socket.read(4) unless @socket.closed?

      # can be nil with some clients, that is no headers were sent again/first time
      return false if payload.nil?

      @tpkt_header = TPKTHeaderParser.new(payload)

      true
    end

    def read_x224_crq
      to_read      = @tpkt_header.data - RDP::TPKT_HEADER_LENGTH # size to read minus the header size
      full_data    = @socket.read(to_read).to_s

      @x224_header = X224Header.new(full_data)

    end

    def read
      result = read_tpkt
      if result
        read_x224_crq
      end

    end

    def explain
      <<-EOF
    TPKT Header Data
      Version: #{@tpkt_header.version}
      Extra Flags: #{@tpkt_header.flags}
      Data + Header size: #{@tpkt_header.data}

    x224Crq Data
      Length indicator: #{@x224_header.length}
      PDU Type: #{@x224_header.pdu_type}, Code #{RDP.x224_tpdu_type[@x224_header.pdu_type]}
      Variable Part: #{@x224_header.variable_part.sub(/\r\n$/, '<<\r\n>>') rescue ''}

      Variable: #{@x224_header.variable}
      Variable Type: #{@x224_header.variable_type}
      #{"Routing IP: #{@x224_header.variable_as_ip}" if @x224_header.variable_type == :routingToken}


      Negotiation Request:
        type:               #{@x224_header.neg_req.type               rescue '' }
        flags:              #{@x224_header.neg_req.flags              rescue '' }
        length:             #{@x224_header.neg_req.length             rescue '' }
        requested_protocol: #{@x224_header.neg_req.requested_protocol rescue '' } (#{@x224_header.neg_req.proto_s rescue ''})

      EOF
    end


  end
end
