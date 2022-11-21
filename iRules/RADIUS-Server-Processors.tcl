when RULE_INIT {

	#====================================================================
	#####################################################################
	#+ Configuration of RADIUS server global options
	#

	set static::RadSRV_rps_quota_interval			3				;# Per-Client Radius request quota interval in seconds
	set static::RadSRV_udp_limit		 		500				;# Global Radius request quota limit
	set static::RadSRV_udp_limit_interval 			1				;# Global Radius request quota interval in seconds
	set static::RadSRV_udp_retransmission_timeout		30				;# UDP retransmission timeout in seconds
	set static::RadSRV_challenge_timeout 			120				;# RADIUS CHALLENGE/RESPONSE session timeout in seconds

	#
	# Configuration of RADIUS server global options
	#####################################################################
	#====================================================================

	#====================================================================
	#####################################################################
	#+ Initializing counters for TMM-specific per-request high speed quotas
	#

	set static::RadSRV_udp_count 				0				;# Dont change this value, its required to initialize the high speed packet limiters
	set static::RadSRV_udp_timer 				[clock seconds]			;# Dont change this value, its required to initialize the high speed packet limiters

	#
	# Initializing counters for TMM-specific per-request high speed quotas
	#####################################################################
	#====================================================================

	#====================================================================
	#####################################################################
	#+ Configuration of TCL script pre-compiler
	#

	set RadSRV_compiler(enable)				1				;# Enable TCL Script compiling (0-1 Bolean)

	set RadSRV_compiler(session_tracing_enable)		1				;# Enable session_state() export/import tracing (0-1 Bolean)
	set RadSRV_compiler(istats_enable)			1				;# Enable istats performance counters (0-1 Bolean)
	set RadSRV_compiler(compression_enable)			1 				;# Enable TCL variable compression (0-1 Bolean)
	set RadSRV_compiler(compression_resolve_globals)	1				;# Enable static::* variable resolving (0-1 Bolean)
	set RadSRV_compiler(remove_unnecessary_lines)		1				;# Enable to remove empty or unnecessary lines of code

	set RadSRV_compiler(log_enable)				1				;# Enable logging (0-1 Bolean)
	set RadSRV_compiler(log_prefix)				"RadSRV : \[virtual\] : "	;# Configure a common log-prefix. Escape TCL commands/variables to allow a execution/substitution during run-time.  
	set RadSRV_compiler(log_level)				6				;# Include the log-lines up to log-level (0-8 See description below)
												;#
												;#	0	Emergency	Not used by this iRule
												;#	1	Alert		Local TMM -subtable discovery
												;#	2	Critical	Not used by this iRule
												;#	3	Error		Not used by this iRule
												;#	4	Warning		Configuration Issues
												;#	5	Notice		Accounting Information (Accept/Reject)
												;#	6	Informational	Requests, responses and preemptive rejects
												;#	7	Debug		Only important debug messages
												;#	8	Trace		Line-by-Line debug messages

	set RadSRV_compiler(perform_local_tmm_discovery)	0				;# DEBUG Mode: Perform TMM local table discovery on each RADIUS request (0-1 Bolean)

	#
	# Configuration of TCL script pre-compiler
	#####################################################################
	#====================================================================

set static::RadSRV_PreProcessor {

	#====================================================================
	#####################################################################
	#+ Handler for RADIUS Protocol Pre-Processor execution
	#

	#####################################################################
	#+ Handler for unique RADIUS request ID generation
	#

	# Note: The variable RadPOL(request_timestamp) could be set within the RADIUS Policy script to support unique logging information.

	if { [info exists RadPOL(request_timestamp)] } then {
		set RadSRV(request_timestamp) $RadPOL(request_timestamp)

		#log7 "The request timestamp was successfully passed from RADIUS Policy script."

	} else {
		set RadSRV(request_timestamp) "[TMM::cmp_unit][clock clicks]"

		#log7 "A fresh request timestamp was successfully generated."

	}

	#
	# Handler for unique RADIUS request ID generation
	#####################################################################

	#log6 "Received UDP packet from \"[IP::client_addr]:[UDP::client_port]\". Starting to process the RADIUS request."
	#log7 "RADIUS Protocol Pre-Processor is executed. Starting to process the RADIUS request."
	#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Received" 1

	#####################################################################
	#+ Handler for high speed UDP packet rate limiting (global)
	#

	#log8 "Increasing the high speed UDP packet limiter counter and checking if the new value exceeds the configured limit."

	if { [incr static::RadSRV_udp_count] > $static::RadSRV_udp_limit } then {

		#log8 "The high speed UDP packet limiter counter value has exceeded the configured limit. Checking if the last recycling timestamp is within the configured limiter interval."

		if { $static::RadSRV_udp_timer + $static::RadSRV_udp_limit_interval > [clock second] } then {

			#log8 "The recycling timestamp is within the configured limiter interval."
			#log6 "The high speed UDP packet rate limiter has been exhausted. Silently discard the request."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Limiter_Exceeded" 1
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

			UDP::drop
			return

		}

		#log8 "The recycling timestamp is outside the configured limiter interval. Resetting the UDP counter value and setting a new recycling timestamp."

		set static::RadSRV_udp_count 0
		set static::RadSRV_udp_timer [clock seconds]

	}

	#log7 "The UDP packet has passed the high speed UDP packet limiter check."

	#
	# Handler for high speed UDP packet rate limiting (global)
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS protocol verification
	#
	# 0               1               2               3               4 byte
	# 0                   1                   2                   3
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	# |      Code     |  Identifier   |            Length             |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                                                               |
	# |                         Authenticator                         |
	# |                           (16 bytes)                          |
	# |                                                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Attr1-Code   |  Attr1-Length |         Attr1-Value           |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Attr1-Value (cont)           |  AttrN-Code   |  AttrN-Length |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                          AttrN-Value (cont) .                 |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  AttrN-Value (cont) .

	#log8 "Performing various checks to see if the received UDP payload is an valid constructed RADIUS request."

	#####################################################################
	#+ Handler for UDP layer verification
	#

	#log8 "Checking if the buffered UDP packet meets the minimum RADIUS request size."

	if { [UDP::payload length] < 20 } then {

		#log6 "The buffered UDP packet size ([UDP::payload length] bytes) is too short for beeing a valid RADIUS request. Silently discard the request."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_TooSmall" 1
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

		UDP::drop
		return

	}

	#log7 "The buffered UDP packet ([UDP::payload length] bytes) meets the minimum RADIUS request size."

	#
	# Handler for UDP layer verification
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS request encapsulation parsing
	#

	#log8 "Extracting the RADIUS request code, ID, length and authenticator fields."

	binary scan [UDP::payload] caSa16\
					RadSRV(request_code)\
					RadSRV(request_id)\
					RadSRV(request_length)\
					RadSRV(request_authenticator)

	#
	# Handler for RADIUS request encapsulation parsing
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS request code evaluation
	#

	#log8 "Evaluate the embedded RADIUS request code."

	if { $RadSRV(request_code) != 1 } then {

		#log6 "The RADIUS request code is not an authentication specific request. Silently discard the request."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Wrong_Code($RadSRV(request_code))" 1
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

		UDP::drop
		return

	}

	#log7 "The RADIUS request code is set to Access-Request." 

	#
	# Handler for RADIUS request code evaluation
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS request size verification
	#

	#log8 "Unsigning the signed 16-bit integer RADIUS request length field value to support reliable math operation."

	set RadSRV(request_length) [expr { $RadSRV(request_length) & 0xffff } ]

	#log8 "Checking if request length is less than 2068 bytes and if the buffered UDP packet size matches the RADIUS request length field value."

	if { $RadSRV(request_length) >= 2068 } then {

		#log4 "The RADIUS request from \"[IP::client_addr]\" is too large for the \[RADIUS::avp\] command. File a F5 support ticket if support for large RADIUS request is required." 
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Too_Large" 1

		#####################################################################
		#+ Handler for RADIUS response rejected construction and sending
		#

		#log6 "Constructing and sending a RADIUS reject response to the RADIUS client."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Response_REJECT" 1
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Send" 1

		UDP::respond [binary format caSa16cca*\
							3\
							$RadSRV(request_id)\
							66\
							[md5\
								[binary format caSa16cca*a*\
											3\
											$RadSRV(request_id)\
											66\
											$RadSRV(request_authenticator)\
											18\
											46\
											"ACCESS REJECTED: RADIUS request is too large"\
											$client_config(shared_key)\
								]\
							]\
							18\
							46\
							"ACCESS REJECTED: RADIUS request is too large"\
			     ]

		#log8 "Flushing UDP request buffer and exiting the iRule."

		UDP::drop
		return

		#
		# Handler for RADIUS response rejected construction and sending
		#####################################################################

	} elseif { $RadSRV(request_length) == [UDP::payload length] } then {

		#log7 "The buffered UDP packet matches the RADIUS request length field value."

	} elseif { $RadSRV(request_length) < [UDP::payload length] } then {

		#log7 "The buffered UDP packet is larger than the RADIUS request length field value (RFC allowed behavior)."
		#log7 "Removing the trailing bytes/paddings so that \[RADIUS::avp\] command stops complaining."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Padded" 1

		UDP::payload replace $RadSRV(request_length) [expr { [UDP::payload length] - $RadSRV(request_length) }] ""

	} else {

		#log6 "The RADIUS request  from \"[IP::client_addr]\" is malformed or fragmented. Silently discard the packet."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Malformated" 1
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

		UDP::drop
		return

	}

	#
	# Handler for RADIUS request size verification
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS attribute encapsulation verification
	#

	#log8 "Verifying the integrity of received attributes by stepping through the individual attribute length fields."

	for { set RadSRV(payload_offset) 20 } { $RadSRV(payload_offset) + 2 <= $RadSRV(request_length) } { incr RadSRV(payload_offset) $RadSRV(request_attribute_length) } {

		#log8 "Extracting the signed 8-bit integer length value of the next RADIUS request attributes field."

		binary scan [UDP::payload] x$RadSRV(payload_offset)xc RadSRV(request_attribute_length)

		#log8 "Unsigning the signed 8-bit integer length value and checking if the attribute length value is at least 2 bytes long to avoid endless while loops."

		if { [set RadSRV(request_attribute_length) [expr { $RadSRV(request_attribute_length) & 0xff } ]] < 2 } then {

			#log6 "An RADIUS attribute length value received from RADIUS client \"[IP::client_addr]\" is malformed. Silently discard the request."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Malformed" 1
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

			UDP::drop
			return

		}

		#log8 "The attribute length value is at least 2 bytes long. Increasing payload offset and checking if remaining attributes exists."

	}

	#log8 "Finished to process the attributes. Checking if the total attribute length of matches our RADIUS request length."

	if { $RadSRV(payload_offset) != $RadSRV(request_length) } then {

			#log6 "The RADIUS attribute(s) received from RADIUS client \"[IP::client_addr]\" are fragmented. Silently discard the request."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_Malformed" 1
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

			UDP::drop
			return

	}

	#log8 "Finished to verify the individual attribute length fields."
	#log7 "The RADIUS attribute encapsulation is correctly constructed."

	#
	# Handler for RADIUS attribute encapsulation verification
	#####################################################################

	#
	# Handler for RADIUS protocol verification
	#####################################################################

	#####################################################################
	#+ Handler for HMAC-based message authenticator attribute verification
	#

	#log8 "Checking if HMAC-based message authenticator attribute usage is required for the RADIUS client."

	if { $client_config(require_hmac) > 0 } then {

		#log8 "HMAC-based RADIUS request message authenticator usage is required."
		#log8 "Checking if the RADIUS request contains a HMAC-based message authenticator attribute."

		if { [string length [set RadSRV(request_hmac) [RADIUS::avp 80]]] == 16 } then {

			#log8 "The RADIUS request contains a HMAC-based message authenticator attribute."
			#log8 "Re-initializing the message authenticator attribute field (16 bytes) with 0x00 values."

			RADIUS::avp replace 80 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

			#log8 "Performing HMAC-MD5 calculation on the initialized UDP payload using clients shared key."
			#log8 "Comparing the HMAC-MD5 calculation result with the received attribute value."

			if { [CRYPTO::sign -alg hmac-md5 -key $client_config(shared_key) [UDP::payload]] eq $RadSRV(request_hmac) } then {

				#log7 "The HMAC-MD5 signature could be sucessfully verified."
				#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_HMAC_Verified" 1

			} else {

				#log6 "The HMAC-MD5 signature from RADIUS client \"[IP::client_addr]\" could not be verified. Silently discard the packet."
				#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_HMAC_Failure" 1
				#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

				UDP::drop
				return

			}

		} else {

			#log6 "A valid HMAC-based message authenticator attribute was not send by RADIUS client \"[IP::client_addr]\". Silently discard the packet."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_HMAC_Missing" 1
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

			UDP::drop
			return

		}

	} else {

		#log7 "HMAC-based message authenticator attribute usage is not required for this RADIUS client."

	}

	#
	# Handler for HMAC-based message authenticator attribute verification
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS client RPS quota enforcement
	#

	#log8 "Checking if the RPS counter for the current RADIUS client has been exhausted."

	if { [table lookup -notouch "RadSRV_quota_[IP::client_addr]"] > $client_config(request_limit) } then {

		#log6 "The RPS counter for RADIUS client \"[IP::client_addr]\" has been exhausted. Silently discard the request."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_RPS_Exceeded_[IP::client_addr]" 1
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Drop" 1

		UDP::drop
		return

	}

	#log7 "The RPS counter for the current RADIUS client is below the configured threshold."

	#
	# Handler for RADIUS client RPS quota enforcement
	#####################################################################

	#####################################################################
	#+ Handler for UDP retransmission and deduplication
	#

	#log8 "Constructing binary RADIUS request table label for \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\""

	set RadSRV(request_state_label) [binary format a*c4c4Iaa*\
								"RadSRV_"\
								[split [getfield [IP::local_addr] "%" 1] "."]\
								[split [getfield [IP::client_addr] "%" 1] "."]\
								[UDP::client_port]\
								$RadSRV(request_id)\
								$RadSRV(request_authenticator)\
					]

	#log8 "Trying to exclusively set our request timestamp value into \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table."

	if { [catch {

		#tmmdiscovery #####################################################################
		#tmmdiscovery #+ Handler to flush TMM local subtable variable on each request
		#tmmdiscovery #
		#tmmdiscovery 	
		#tmmdiscovery #log1 "!!!WARNING!!! Flushing the TMM local -subtable variable for debug purposes !!!WARNING!!!"
		#tmmdiscovery 		
		#tmmdiscovery unset -nocomplain static::local_tmm_subtable
		#tmmdiscovery 
		#tmmdiscovery #
		#tmmdiscovery #+ Handler to flush TMM local subtable variable on each request
		#tmmdiscovery #####################################################################

		#log8 "CATCH: Checking if a local TMM core -subtable label has already been discovered by accesing the runtime generated variable \"\$static::local_tmm_subtable\""

		set RadSRV(request_state) [table set\
							-notouch\
							-excl\
							-subtable $static::local_tmm_subtable\
							$RadSRV(request_state_label)\
							"recv|$RadSRV(request_timestamp)"\
							indef\
							$static::RadSRV_udp_retransmission_timeout\
					  ]

		#log8 "CATCH: The local TMM core -subtable label has already been discovered. The local TMM core subtable lable is \"$static::local_tmm_subtable\"."

	}] } then {

		#log8 "CATCH: A local TMM core -subtable label has not been discovered yet. Starting to discover a local TMM core subtable lable."

		#####################################################################
		#+ Handler for local TMM subtable label discovery
		#

		#log1 "A local TMM core -subtable label has not been discovered yet on TMM \"[TMM::cmp_unit]\"."
		#log1 "Setting the discovery iterations to the TMM count of the underlying unit \"[TMM::cmp_count]\" multiplied by 7 (just a lucky number)."

		set tmm(table_iterations) [expr { [TMM::cmp_count] * 7 }]

		#log1 "Constructing a bunch of -subtable labels and measuring their individual response times."

		for { set tmm(x) 0 } { $tmm(x) < $tmm(table_iterations) } { incr tmm(x) } {

			#log1 "Measuring the time needed for -subtable \"tmm_local_$tmm(x)\"."

			set tmm(start_timestamp) [clock clicks]

			table lookup -subtable "tmm_local_$tmm(x)" [clock clicks]

			set tmm(stop_timestamp) [clock clicks]

			#log1 "It took \"[expr { $tmm(stop_timestamp) - $tmm(start_timestamp) }]\" clicks to get an response from -subtable \"tmm_local_$tmm(x)\"."

			set tmm_times([expr { $tmm(stop_timestamp) - $tmm(start_timestamp) }]) $tmm(x)

		}

		#log1 "Finished the measurement of response times of the individual -subtable labels."
		#log1 "The -subtable label \"tmm_local_$tmm_times([lindex [lsort -increasing -integer [array names tmm_times]] 0])\" was the fastest. It has responded in \"[lindex [lsort -increasing -integer [array names tmm_times]] 0]\" clicks."

		set static::local_tmm_subtable "tmm_local_$tmm_times([lindex [lsort -increasing -integer [array names tmm_times]] 0])"

		#istats ISTATS::set "ltm.virtual [virtual name] c RadSRV_TMM[TMM::cmp_unit]_TableTime" [lindex [lsort -increasing -integer [array names tmm_times]] 0]
		#istats ISTATS::set "ltm.virtual [virtual name] s RadSRV_TMM[TMM::cmp_unit]_TableLabel" $static::local_tmm_subtable

		# 
		# Handler for local TMM subtable label discovery
		#####################################################################

		#####################################################################
		#+ Handler for TCL [catch] excemption command retry
		#

		#log8 "Trying again to exclusively set our request timestamp value into \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table." 

		set RadSRV(request_state) [table set\
							-notouch\
							-excl\
							-subtable $static::local_tmm_subtable\
							$RadSRV(request_state_label)\
							"recv|$RadSRV(request_timestamp)"\
							indef\
							$static::RadSRV_udp_retransmission_timeout\
					  ]

		#
		# Handler for TCL [catch] excemption command retry
		#####################################################################

	}

	#log8 "Checking the request timestamp of the \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table entry."

	if { $RadSRV(request_state) eq "recv|$RadSRV(request_timestamp)" } then {

		#log7 "The \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table entry holds our request timestamp. We have the exclusiveness to further process this RADIUS request."

	} elseif { $RadSRV(request_state) starts_with "recv|" } then {

		#log8 "The \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table contains a request timestamp of a previously received UDP datagram."
		#log6 "The received RADIUS request is still processed by the RADIUS policy. Silently discard the duplicated request."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Duplicate" 1

		UDP::drop
		return

	} else {

		#log6 "The \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" session table holds the buffered RADIUS response of a previously send UDP packet. Retransmiting the buffered RADIUS response."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Retransmit" 1

		UDP::respond $RadSRV(request_state)
		UDP::drop
		return

	}

	#
	# Handler for UDP retransmission and deduplication
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS client RPS quota update
	#

	#log8 "Increasing the RPS counter value for the RADIUS client."

	if { [table incr -mustexist "RadSRV_quota_[IP::client_addr]"]  eq "" } then {

		#log7 "An existing RPS counter value does not exist before. Initializing the RPS counter value with configurable timeouts."

		table set "RadSRV_quota_[IP::client_addr]" 1 indef $static::RadSRV_rps_quota_interval

	}

	#
	# Handler for RADIUS client RPS quota update
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS proxy-state attribute relaying
	#

	#log8 "Checking if RADIUS request contains proxy-state attribute(s) to support RADIUS responses through RADIUS proxy servers."

	if { [RADIUS::avp 33] ne "" } then {

		#log8 "The RADIUS request contains proxy-state attribute(s). Skipping through the individual proxy-state attributes from start to end of the RADIUS request."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Request_ProxyState_Relaying" 1

		for { set RadSRV(x) 0 } { [RADIUS::avp 33 index $RadSRV(x)] ne "" } { incr RadSRV(x) } {

			#log8 "Found a proxy-state attribute. Constructing a coresponding proxy-state RADIUS response attribute."

			append RadSRV(response_attributes_field) [binary format cca*\
										33\
										[expr { 2 + [string length [RADIUS::avp 33 index $RadSRV(x)]] }]\
										[RADIUS::avp 33 index $RadSRV(x)] ]

		}

		#log7 "Finished to collect the individual proxy-state attribute(s) from the RADIUS request."

	} else {

		#log7 "The RADIUS request does not contain any proxy-state attribute(s)."

		set RadSRV(response_attributes_field) ""

	}

	#
	# Handler for RADIUS proxy-state attribute relaying
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS session state lookup / initialization
	#

	#log8 "Checking if the RADIUS request contains a session state attribute."

	if { [RADIUS::avp 24] ne "" } then {

		#log8 "The RADIUS request does contain a session state attribute. Checking if the provided state value references to an active RADIUS session."

		if { [set RadSRV(session_state_array) [table lookup -notouch "RadSRV_state_[RADIUS::avp 24]"]] ne "" } then {

			#log6 "The user \"[RADIUS::avp 1]\" continues CHALLENGE / RESPONSE session with ID = \"[RADIUS::avp 24]\" via NAS-Identifier=\"[RADIUS::avp 32]\" at NAS-IP-Address=\"[RADIUS::avp 4 ip4]\"."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Session_Restore" 1

			array set session_state $RadSRV(session_state_array)

			#session #####################################################################
			#session #+ Handler for RADIUS session logging
			#session #

			#sessionlog "Importing session_state() variables for CHALLENGE / RESPONSE session ID = \"$session_state(id)\"."
			#sessionlog "[string repeat "\u0023" 30] Imported session state [string repeat "\u0023" 30]" 
			#session foreach { RadSRV(session_state_variable) RadSRV(session_state_variable_value) } $RadSRV(session_state_array) {
				#sessionlog "session_state($RadSRV(session_state_variable)) = [URI::encode $RadSRV(session_state_variable_value)]" 
			#session }
			#sessionlog "[string repeat "\u0023" 30] Imported session state [string repeat "\u0023" 30]" 

			#session #
			#session # Handler for RADIUS session logging
			#session #####################################################################

			#log7 "Deleting the session state information from RADIUS session table to free memory."

			table delete "RadSRV_state_[RADIUS::avp 24]"

		} else {

			#log6 "The user \"[RADIUS::avp 1]\" tried to continue an obsolete CHALLENGE / RESPONSE session with ID = \"[RADIUS::avp 24]\" via NAS-Identifier=\"[RADIUS::avp 32]\" at NAS-IP-Address=\"[RADIUS::avp 4 ip4]\""
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Session_Failure" 1

			#####################################################################
			#+ Handler for RADIUS response construction
			#

			#log8 "Calculating the total length of the RADIUS response (RADIUS encapsulation length + static attributes length + dynamic attribute length."

			set RadSRV(response_length) [expr { 20 + 43 + [string length $RadSRV(response_attributes_field)] }]

			#log8 "Constructing RADIUS reject response for the RADIUS client."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Response_REJECT" 1

			set RadSRV(response_payload) [binary format caSa16cca*a*\
										3\
										$RadSRV(request_id)\
										$RadSRV(response_length)\
										[md5\
											[binary format caSa16cca*a*a*\
															3\
															$RadSRV(request_id)\
															$RadSRV(response_length)\
															$RadSRV(request_authenticator)\
															18\
															43\
															"ACCESS REJECTED: RADIUS session timed out"\
															$RadSRV(response_attributes_field)\
															$client_config(shared_key)\
											]\
										]\
										18\
										43\
										"ACCESS REJECTED: RADIUS session timed out"\
										$RadSRV(response_attributes_field)\
						      ]

			#log8 "Successfully constructed RADIUS reject response for the RADIUS client."

			#
			# Handler for RADIUS response construction
			#####################################################################

			#####################################################################
			#+ Handler for RADIUS request state update
			#

			#log7 "Updating the session table entry \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" = \"UDP Payload\" to support UDP retransmissions."

			table set\
				-notouch\
				-subtable $static::local_tmm_subtable\
				$RadSRV(request_state_label)\
				$RadSRV(response_payload)\
				indef\
				$static::RadSRV_udp_retransmission_timeout

			#
			# Handler for RADIUS request state update
			#####################################################################

			#####################################################################
			#+ Handler for RADIUS response sending
			#

			#log7 "Sending the constructed RADIUS response packet to the client."
			#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Send" 1

			UDP::respond $RadSRV(response_payload)
			UDP::drop
			return 

			#
			# Handler for RADIUS response sending
			#####################################################################

		}

	} else {

		#log7 "The RADIUS request does not contain a session state attribute. Initializing a fresh session state for this request."

		set session_state(action) 1

	}

	#
	# Handler for RADIUS session state lookup / initialization
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS request password attribute decryption
	#

	#log8 "Checking if the RADIUS request contains an encrypted user-password attribute spanning one or multiple 16-byte / 128-bit cipher block(s)."

	if { [RADIUS::avp 2] eq "" } then {

		#log7 "The RADIUS request does not contain an encrypted password attribute. Skipping the password decryption."

	} elseif { [string length [RADIUS::avp 2]] == 16 } then {

		#log8 "The RADIUS request contains an encrypted password value stored in one 16-byte / 128-bit cipher block. Using an optimized function to encrypt the contained password value."
		#log8 "Chunking and converting the encrypted password value into two subsequent 64-bit integer values."

		binary scan [RADIUS::avp 2] WW\
						RadSRV(encrypted_password_64bit_chunk_1)\
						RadSRV(encrypted_password_64bit_chunk_2)

		#log8 "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and the random value provided in the RADIUS request authenticator field."
		#log8 "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

		binary scan [md5 "$client_config(shared_key)$RadSRV(request_authenticator)"] WW\
												RadSRV(encryption_key_64bit_chunk_1)\
												RadSRV(encryption_key_64bit_chunk_2)

		#log8 "Performing XOR operation with the corresponding cipher block / encryption key 64-bit integer values."

		lappend RadSRV(plaintext_password_64bit_chunks) [expr { $RadSRV(encrypted_password_64bit_chunk_1) ^ $RadSRV(encryption_key_64bit_chunk_1) }]\
														[expr { $RadSRV(encrypted_password_64bit_chunk_2) ^ $RadSRV(encryption_key_64bit_chunk_2) }]

		#log8 "Converting the two decrypted 64-bit integer password values to their binary representation while removing possible paddings used to fill the cipher block."

		binary scan [binary format W* $RadSRV(plaintext_password_64bit_chunks)] A* RadSRV(plaintext_password)

		#log7 "Replacing the encrypted password value with the decrypted and truncated password value."

		RADIUS::avp replace 2 $RadSRV(plaintext_password)

	} elseif { [string length [RADIUS::avp 2]] % 16 == 0 } then {

		#log8 "The encrypted password is stored in more than two 128-bit cipher block(s). Using the generic function to encrypt the contained password value."
		#log8 "Chunking and converting the encrypted password value into a list of subsequent 64-bit integer values."

		binary scan [RADIUS::avp 2] W* RadSRV(encrypted_password_64bit_chunks)

		#log8 "Set the initial key seed to the random value provided in the RADIUS request authenticator field."

		set RadSRV(encryption_iv) $RadSRV(request_authenticator)

		#log8 "Looping pair-wise through the list of encrypted password chunks to decrypt a full cipher block and then rotate the key for the next block."

		foreach { RadSRV(encrypted_password_64bit_chunk_1) RadSRV(encrypted_password_64bit_chunk_2) } $RadSRV(encrypted_password_64bit_chunks) {

			#log8 "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and current key seed as input."
			#log8 "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

			binary scan [md5 "$client_config(shared_key)$RadSRV(encryption_iv)"] WW RadSRV(encryption_key_64bit_chunk_1) RadSRV(encryption_key_64bit_chunk_2)

			#log8 "Performing XOR operation with the corresponding cipher block / encryption key 64-bit integer values."
			#log8 "Appending the retrieved plaintext 64-bit chunks to the list of already decrypted values."

			lappend RadSRV(plaintext_password_64bit_chunks) [expr { $RadSRV(encrypted_password_64bit_chunk_1) ^ $RadSRV(encryption_key_64bit_chunk_1) }]\
									[expr { $RadSRV(encrypted_password_64bit_chunk_2) ^ $RadSRV(encryption_key_64bit_chunk_2) }]

			#log8 "Setting the encryption key seed for the next cipher block to the cipher value of the current cipher block."

			set RadSRV(encryption_iv) [binary format WW $RadSRV(encrypted_password_64bit_chunk_1) $RadSRV(encrypted_password_64bit_chunk_2)]

		}

		#log8 "Converting the 64-bit integer plaintext password values to their binary representation and removing possible paddings used to fill the last cipher block."

		binary scan [binary format W* $RadSRV(plaintext_password_64bit_chunks)] A* RadSRV(plaintext_password)

		#log7 "Replacing the crypted password attribute with the plaintext password value."

		RADIUS::avp replace 2 $RadSRV(plaintext_password)

	} else {

		#log7 "The encrypted password attribute is malformed. Skipping the password decryption and removing the encrypted password attribute from the request."

		RADIUS::avp replace 2 ""

	}

	#
	# Handler for RADIUS request password attribute decryption
	#####################################################################

	#log7 "Initializing an empty response attribute variable."

	set client_response(attributes) ""

	#log7 "RADIUS Protocol Pre-Processor has successfully finished its execution. Handing over to the RADIUS Policy."

	#
	# Handler for RADIUS Protocol Pre-Processor execution
	#####################################################################
	#====================================================================

}
set static::RadSRV_PostProcessor {

	#====================================================================
	#####################################################################
	#+ Handler for RADIUS Protocol Post-Processor execution
	#

	#log7 "RADIUS Protocol Post-Processor is executed. Starting to process the RADIUS policy information."

	#####################################################################
	#+ Handler for RADIUS response code enumeration
	#

	#log8 "Evaluating the selected RADIUS response action."

	if { ( [info exists client_response(code)] )
	 and ( $client_response(code) eq "ACCEPT" ) } then {

		#log5 "The user \"[RADIUS::avp 1]\" has been granted access to NAS-Identifier=\"[RADIUS::avp 32]\" at NAS-IP-Address=\"[RADIUS::avp 4 ip4]\"."
		#log7 "The RADIUS response action is set to ACCEPT. Setting the RADIUS response code to \"2\"."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Response_ACCEPT" 1

		set client_response(code) 2

	} elseif { ( [info exists client_response(code)] )
	       and ( $client_response(code) eq "CHALLENGE" ) } then {

		#log6 "The user \"[RADIUS::avp 1]\" has been CHALLENGED to provide additional Information via NAS-Identifier=\"[RADIUS::avp 32]\" at NAS-IP-Address=\"[RADIUS::avp 4 ip4]\"."
		#log7 "The RADIUS response action is set to CHALLENGE. Setting the RADIUS response code to \"11\" and initializing the CHALLANGE/RESPONSE session handling."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Response_CHALLENGE" 1

		set client_response(code) 11

		#log8 "Checking if a RADIUS response message has been set by the RADIUS policy."

		if { [info exists client_response(message)] } then {

			#log8 "Adding the configured response message as Reply-Message(18) attribute into the list of RADIUS response attributes."

			lappend client_response(attributes) 18 string $client_response(message)

		}

		#log8 "Adding the current request timestamp as State(24) attribute to identify the next RADIUS request for this CHALLENGE response."

		lappend client_response(attributes) 24 string $RadSRV(request_timestamp)

		#####################################################################
		#+ Handler for RADIUS session state update
		#

		#log8 "Storing the current request timestamp into the session_state(id) array variable."

		set session_state(id) $RadSRV(request_timestamp)

		#log7 "Storing the session_state() array information of the current RADIUS request into RADIUS server session table using the current request timestamp as identifier."

		table set\
			-notouch\
			"RadSRV_state_$RadSRV(request_timestamp)"\
			[array get session_state]\
			indef\
			$static::RadSRV_challenge_timeout

		#
		# Handler for RADIUS session state update
		#####################################################################

		#session #####################################################################
		#session #+ Handler for RADIUS session logging
		#session #

		#sessionlog "Exporting session_state() variables for CHALLENGE / RESPONSE session ID = \"$session_state(id)\"."
		#sessionlog "[string repeat "\u0023" 30] Exported session state [string repeat "\u0023" 30]" 
		#session foreach { RadSRV(session_state_variable) RadSRV(session_state_variable_value) } [array get session_state] {
			#sessionlog "session_state($RadSRV(session_state_variable)) = [URI::encode $RadSRV(session_state_variable_value)]" 
		#session }
		#sessionlog "[string repeat "\u0023" 30] Exported session state [string repeat "\u0023" 30]" 

		#session #
		#session # Handler for RADIUS session logging
		#session #####################################################################

	} else {

		#log5 "The user \"[RADIUS::avp 1]\" has been denied access to NAS-Identifier=\"[RADIUS::avp 32]\" at NAS-IP-Address=\"[RADIUS::avp 4 ip4]\"."
		#log7 "The default RADIUS response action is set to REJECT. Setting the RADIUS response code to \"3\"."
		#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_Response_REJECT" 1

		set client_response(code) 3

		#log8 "Checking if a RADIUS response message has been set by the RADIUS policy."

		if { [info exists client_response(message)] } then {

			#log8 "Adding the configured response message as Reply-Message(18) attribute into the list of RADIUS response attributes."

			lappend client_response(attributes) 18 string $client_response(message)

		}

	}

	#
	# Handler for RADIUS response code enumeration
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS response attribute construction
	#
	# 0               1               2               3               4 byte
	# 0                   1                   2                   3
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Attr1-Code   |  Attr1-Length |         Attr1-Value           |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |       Attr1-Value (cont)      |  AttrN-Code   |  AttrN-Length |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                        AttrN-Value (cont)                     |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  AttrN-Value (cont) .

	#log8 "Checking if user defined RADIUS response attributes are specified for the RADIUS response."

	if { $client_response(attributes) ne "" } then {

		#log8 "RADIUS response attributes are specified for the ongoing RADIUS response. Checking validity of the RADIUS response attributes."

		if { [llength $client_response(attributes)] % 3 == 0 } then {

			#log8 "The specified RADIUS response attributes are correctly formatted. Skipping through the list of RADIUS response attributes to construct the RADIUS attribute field."

			foreach { RadSRV(response_attribute_type) RadSRV(response_attribute_format) RadSRV(response_attribute_value) } $client_response(attributes) {

				#log8 "Processing an attribute with code \"$RadSRV(response_attribute_type)\". Checking if RADIUS response attribute has an empty value."

				if { $RadSRV(response_attribute_value) eq "" } then {

					#log8 "The attribute value is empty. Omitting the addition of the empty value attribute."

					continue

				} elseif { [string length $RadSRV(response_attribute_value)] > 256 } then {

					#log4 "The provided RADIUS response attribute value is to large. Overwriting the RADIUS response code to REJECT!!"

					set client_response(code) 3

				}

				#log8 "The attribute to be insert has a value set. Checking the data type of the attribute and apply proper formatting."

				switch -exact -- $RadSRV(response_attribute_format) {

					"int16" {

						#log8 "Convert the attribute value from int16() to its binary representation."

						set RadSRV(response_attribute_value) [binary format S* $RadSRV(response_attribute_value)]

					}
					"int32" {

						#log8 "Convert the attribute value from int32() to its binary representation."

						set RadSRV(response_attribute_value) [binary format I* $RadSRV(response_attribute_value)]

					}
					"int64" {

						#log8 "Convert the attribute value from int64() to its binary representation."

						set RadSRV(response_attribute_value) [binary format W* $RadSRV(response_attribute_value)]

					}
					"hex" {

						#log8 "Convert the attribute value from hex() to its binary representation."

						set RadSRV(response_attribute_value) [binary format H* $RadSRV(response_attribute_value)]

					}
					"b64" {

						#log8 "Convert the attribute value from base64() to its binary representation."

						set RadSRV(response_attribute_value) [b64decode $RadSRV(response_attribute_value)]

					}
					"ipv4" {

						#log8 "Convert the attribute value from IPv4 notation to its binary representation."

						set RadSRV(response_attribute_value) [binary format c4 [split $RadSRV(response_attribute_value) "."]]

					}
					"ipv4prefix" {

						#log8 "Convert the attribute value from IPv4-CIDR notation to its binary representation."

						set RadSRV(response_attribute_value) [binary format ccc4\
													0\
													[findstr $RadSRV(response_attribute_value) "/" 1]\
													[split [substr $RadSRV(response_attribute_value) 0 "/"] "."]\
										     ]

					}
					"ipv6" {

						#log8 "Convert the attribute value from IPv6 notation to its binary representation."

						set RadSRV(response_attribute_value) [binary format H* [join [split $RadSRV(response_attribute_value) ":"] ""]]

					}
					"ipv6prefix" {

						#log8 "Convert the attribute value from IPv6-CIDR notation to its binary representation."

						set RadSRV(response_attribute_mask)  [findstr $RadSRV(response_attribute_value) "/" 1]
						set RadSRV(response_attribute_value) [binary format ccH[expr { 2 + int(( $RadSRV(response_attribute_value) - 1) / 8) * 2 }]\
																			0\
																			[findstr $RadSRV(response_attribute_value) "/" 1]\
																			[join [split [substr $RadSRV(response_attribute_value) 0 "/" ] ":"] ""]\
										     ]

					}
					default {

						#log8 "The attribute value is already an octet stream and does not require converting."

					}

				}

				#log8 "Constructing the RADIUS response attribute and adding it to the list of existing response attributes."

				append RadSRV(response_attributes_field) [binary format cca*\
												$RadSRV(response_attribute_type)\
												[expr { 2 + [string length $RadSRV(response_attribute_value)] }]\
												$RadSRV(response_attribute_value)\
									 ]


				#log8 "Checking if another attribute needs to be insert."

			}

			#log7 "Finished construction of the RADIUS response attribute fields."

		} else {

			#log4 "The provided RADIUS response attributes are incorrectly formatted. Overwriting the RADIUS response code to REJECT!!"

			set client_response(code) 3

		}

	} else {

		#log7 "User defined RADIUS response attributes are not specified for the RADIUS response."

	}

	#
	# Handler for RADIUS response attribute construction
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS response construction
	#
	# 0               1               2               3               4 byte
	# 0                   1                   2                   3
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	# |      Code     |  Identifier   |            Length             |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                                                               |
	# |                         Authenticator                         |
	# |                           (16 bytes)                          |
	# |                                                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                   Response Attributes (X bytes)               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |     80 (ID)   |   18 (Length) |  Optional HMAC Checksum...	  |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Optional HMAC Checksum  (16 bytes)...

	#log8 "Calculating the total length of the RADIUS response (RADIUS encapsulation length + dynamic attribute length)."

	set RadSRV(response_length) [expr { 20 + [string length $RadSRV(response_attributes_field)] }]

	#log8 "Checking if HMAC-based message authenticator attribute usage is required for the RADIUS client."

	if { $client_config(require_hmac) == 2 } then {

		#log7 "HMAC-based RADIUS message authenticator usage is required. Calculating the RADIUS response message authenticator attribute."
		#log8 "Performing HMAC-MD5 calculation using the client shared key on the RADIUS response packet including the initialized message authenticator attribute (16 octets of zero)."

		append RadSRV(response_attributes_field) [binary format cca*\
									80\
									18\
									[CRYPTO::sign -alg hmac-md5 -key $client_config(shared_key)\
										[binary format caSa16a*cca*\
													$client_response(code)\
													$RadSRV(request_id)\
													[incr RadSRV(response_length) 18]\
													$RadSRV(request_authenticator)\
													$RadSRV(response_attributes_field)\
													80\
													18\
													"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
										]\
									]\
							 ]

	} else {

		#log7 "HMAC-based message authenticator attribute usage is not required for this RADIUS client."

	}

	#log7 "Constructing a RADIUS response for the RADIUS client."

	set RadSRV(response_payload) [binary format caSa16a*\
							$client_response(code)\
							$RadSRV(request_id)\
							$RadSRV(response_length)\
							[md5\
								[binary format caSa16a*a*\
											$client_response(code)\
											$RadSRV(request_id)\
											$RadSRV(response_length)\
											$RadSRV(request_authenticator)\
											$RadSRV(response_attributes_field)\
											$client_config(shared_key)\
								]\
							]\
							$RadSRV(response_attributes_field)\
				     ]

	#
	# Handler for RADIUS response construction
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS request state update
	#

	#log7 "Updating the session table entry \"Local IP+Source IP+Source Port+Request ID+Request Authenticator\" = \"UDP Payload\" to support UDP retransmissions."

	table set\
		-notouch\
		-subtable $static::local_tmm_subtable\
		$RadSRV(request_state_label)\
		$RadSRV(response_payload)\
		indef\
		$static::RadSRV_udp_retransmission_timeout

	#
	# Handler for RADIUS request state update
	#####################################################################

	#####################################################################
	#+ Handler for RADIUS response sending
	#

	#log6 "Sending the RADIUS response packet to the client."
	#istats ISTATS::incr "ltm.virtual [virtual name] c RadSRV_UDP_Packet_Send" 1

	UDP::respond $RadSRV(response_payload)
	UDP::drop

	#
	# Handler for RADIUS response sending
	#####################################################################

	#log7 "RADIUS Protocol Post-Processor has successfully finished its execution. Closing the UDP session."

	#
	# Handler for RADIUS Protocol Post-Processor execution
	#####################################################################
	#====================================================================

}

	#====================================================================
	#####################################################################
	#+ Execution of TCL script pre-compiler
	#

	if { $RadSRV_compiler(enable) == 1 } then {

		#####################################################################
		#+ Handler to define the TCL pre-compiler search/replace map
		#

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Initializing RADIUS server script optimization and pre-compiling."

		set RadSRV_compiler(replace_map) ""

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Enumerating the enabled RADIUS server script optimizations."

		if { $RadSRV_compiler(compression_enable) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): RADIUS server script syntax compression is enabled. Importing variable compression compile map."

			# Note: Sorted in alphabetical order where each variable is truncated to a unique abbreviation to speed up variable lookups (cpu and memory savings).

			lappend RadSRV_compiler(replace_map) \
				" \]"						"\]"		\
				RadSRV(encrypted_password_64bit_chunk_1)	"{ep641}"	\
				RadSRV(encrypted_password_64bit_chunk_2)	"{ep642}"	\
				RadSRV(encrypted_password_64bit_chunks)		"{ep64}"	\
				RadSRV(encryption_key_64bit_chunk_1)		"{ek641}"	\
				RadSRV(encryption_key_64bit_chunk_2)		"{ek642}"	\
				RadSRV(encryption_iv)				"{iv}"		\
				RadSRV(plaintext_password_64bit_chunks)		"{pp64}"	\
				RadSRV(plaintext_password)			"{pp}"		\
				RadSRV(payload_offset)				"{off}"		\
				RadSRV(request_attribute_length)		"{qal}"		\
				RadSRV(request_authenticator)			"{qa}"		\
				RadSRV(request_code)				"{qc}"		\
				RadSRV(request_hmac)				"{qh}"		\
				RadSRV(request_id)				"{qi}"		\
				RadSRV(request_state_label)			"{qsl}"		\
				RadSRV(request_state)				"{qs}"		\
				RadSRV(request_timestamp)			"{rt}"		\
				RadSRV(request_length)				"{ql}"		\
				RadSRV(request_state)				"{qs}"		\
				RadSRV(response_attribute_type) 		"{rat}"		\
				RadSRV(response_attribute_format) 		"{rafo}"	\
				RadSRV(response_attribute_mask) 		"{ram}"		\
				RadSRV(response_attribute_value) 		"{rav}"		\
				RadSRV(response_attributes_field)		"{raf}"		\
				RadSRV(response_length)				"{rl}"		\
				RadSRV(response_payload)			"{rp}"		\
				RadSRV(session_state_array)			"{ssa}"		\
				RadSRV(session_state_variable) 			"{ssv}"		\
				RadSRV(session_state_variable_value)		"{ssvv}"	\
				RadSRV(x)					"{x}"		\
				tmm(table_iterations)				"{ti}"		\
				tmm(start_timestamp)				"{t1}"		\
				tmm(stop_timestamp)				"{t2}"		\
				tmm(x)						"{tx}"		\
				"tmm_times"					"tt"		\
				"tmm_local_"					"tmm_local_"	\
				"ACCEPT"					"ACCEPT"	\
				"CHALLENGE"					"CHALLENGE"	\
				"REJECT"					"REJECT"	\
				RadPOL(request_timestamp)			RadPOL(request_timestamp)	\
				client_config(shared_key)			client_config(shared_key)	\
				client_config(require_hmac)			client_config(require_hmac)	\
				client_config(request_limit)			client_config(request_limit)	\
				client_response(code)				client_response(code)		\
				client_response(message)			client_response(message)	\
				client_response(attributes)			client_response(attributes)	\
				"session_state("				"session_state("		\
				"static::local_tmm_subtable"			"static::local_tmm_subtable"

		}

		if { $RadSRV_compiler(compression_resolve_globals) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): The resolving of static::* configuration options is enabled. Resolving the global variables and importing their values to the compression compile map."

			lappend RadSRV_compiler(replace_map) \
				"\$static::RadSRV_udp_limit_interval"		$static::RadSRV_udp_limit_interval		\
				"\$static::RadSRV_udp_limit"			$static::RadSRV_udp_limit			\
				"\$static::RadSRV_udp_retransmission_timeout"	$static::RadSRV_udp_retransmission_timeout	\
				"\$static::RadSRV_challenge_timeout"		$static::RadSRV_challenge_timeout		\
				"\$static::RadSRV_rps_quota_interval"		$static::RadSRV_rps_quota_interval

		}

		if { $RadSRV_compiler(log_enable) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): RADIUS server script logging is enabled. Constructing the log-prefix."

			set RadSRV_compiler(log_prefix) [string map $RadSRV_compiler(replace_map) "$RadSRV_compiler(log_prefix)\$RadSRV(request_timestamp) :"]

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Importing compile map for log level = \"$RadSRV_compiler(log_level)\"."

			for { set RadSRV_compiler(x) 0 } { $RadSRV_compiler(x) <= $RadSRV_compiler(log_level) } { incr RadSRV_compiler(x) } {
				switch -exact -- $RadSRV_compiler(x) {
					0 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.emerg \"$RadSRV_compiler(log_prefix) " }
					1 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.alert \"$RadSRV_compiler(log_prefix) " }
					2 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.crit \"$RadSRV_compiler(log_prefix) " }
					3 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.error \"$RadSRV_compiler(log_prefix) " }
					4 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.warn \"$RadSRV_compiler(log_prefix) " }
					5 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.notice \"$RadSRV_compiler(log_prefix) " }
					6 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.info \"$RadSRV_compiler(log_prefix) " }
					7 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.debug \"$RadSRV_compiler(log_prefix) " }
					8 { lappend RadSRV_compiler(replace_map) "#log$RadSRV_compiler(x) \"" "log -noname local0.debug \"$RadSRV_compiler(log_prefix) " }
				}
			}
		}

		if { $RadSRV_compiler(session_tracing_enable) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): RADIUS server session logging is enabled. Importing compile map to enable RADIUS session logging."

			lappend RadSRV_compiler(replace_map) "#sessionlog \"" "log -noname local0.debug \"$RadSRV_compiler(log_prefix) "
			lappend RadSRV_compiler(replace_map) "#session " ""

		}

		if { $RadSRV_compiler(istats_enable) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): RADIUS server statistics are enabled. Importing compile map to enable istats collectors."

			lappend RadSRV_compiler(replace_map) "#istats " ""
		}

		if { $RadSRV_compiler(perform_local_tmm_discovery) == 1 } then {

			log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Pre-Request flushing of the TMM local -subtable variable is enabled. Importing compile map to unset the variable."

			lappend RadSRV_compiler(replace_map) "#tmmdiscovery " ""
		}

		#
		# Handler to define the TCL pre-compiler search/replace map
		#####################################################################

		#####################################################################
		#+ Handler to pre-compile the RADIUS Protocol Pre-Processor TCL script
		#

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Applying the search/replace map to the original RADIUS Pre-Processor TCL script."

		set static::RadSRV_PreProcessor [string map $RadSRV_compiler(replace_map) $static::RadSRV_PreProcessor]

		if { $RadSRV_compiler(remove_unnecessary_lines) } then {

			set RadSRV_compiler(bunch_of_code) ""
			foreach RadSRV_compiler(line_of_code) [split $static::RadSRV_PreProcessor "\n"] {
				switch -glob -- $RadSRV_compiler(line_of_code) {
					"*	#+*" {
						# Keep the script line with important comments
						set RadSRV_compiler(line_feed) [substr $RadSRV_compiler(line_of_code) 0 "#"]
						lappend RadSRV_compiler(bunch_of_code) "" "$RadSRV_compiler(line_feed)#" $RadSRV_compiler(line_of_code) "$RadSRV_compiler(line_feed)#" ""
					}
					"" - "*	#*"	{
						# Remove the empty or unnessesary script lines
					}
					default {
						# Keep the script line with actual code
						lappend RadSRV_compiler(bunch_of_code) $RadSRV_compiler(line_of_code)
					}
				}

			}

			set static::RadSRV_PreProcessor [join $RadSRV_compiler(bunch_of_code) "\n"]

		}

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Finished to pre-compile the RADIUS Pre-Processor TCL script. Storing it to \"\$static::RadSRV_PreProcessor\"."

		#
		# Handler to pre-compile the RADIUS Protocol Pre-Processor TCL script
		#####################################################################

		#####################################################################
		#+ Handler to pre-compile the RADIUS Protocol Post-Processor TCL script
		#

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Applying the search/replace map to the original RADIUS Post-Processor TCL script."

		set static::RadSRV_PostProcessor [string map $RadSRV_compiler(replace_map) $static::RadSRV_PostProcessor]

		if { $RadSRV_compiler(remove_unnecessary_lines) } then {

			set RadSRV_compiler(bunch_of_code) ""
			foreach RadSRV_compiler(line_of_code) [split $static::RadSRV_PostProcessor "\n"] {
				switch -glob -- $RadSRV_compiler(line_of_code) {
					"*	#+*" {
						# Keep the script line with important comments
						set RadSRV_compiler(line_feed) [substr $RadSRV_compiler(line_of_code) 0 "#"]
						lappend RadSRV_compiler(bunch_of_code) "" "$RadSRV_compiler(line_feed)#" $RadSRV_compiler(line_of_code) "$RadSRV_compiler(line_feed)#" ""
					}
					"" - "*	#*" {
						# Remove the empty or unnessesary script lines
					}
					default {
						# Keep the script line with necessary code
						lappend RadSRV_compiler(bunch_of_code) $RadSRV_compiler(line_of_code)
					}
				}

			}

			set static::RadSRV_PostProcessor [join $RadSRV_compiler(bunch_of_code) "\n"]

		}

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Finished to pre-compile the RADIUS Post-Processor TCL script. Storing it to \"\$static::RadSRV_PostProcessor\"."

		#
		# Handler to pre-compile the RADIUS Protocol Post-Processor TCL script
		#####################################################################

		log -noname local0.debug "RadSRV compiler : (TMM[TMM::cmp_unit]): Successfully finished pre-compilation of the PreProcessor and PostProcessor TCL scripts."

	}

	unset -nocomplain RadSRV_compiler

	#
	# Execution of TCL script pre-compiler
	#####################################################################
	#====================================================================

}