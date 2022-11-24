# About

The included TCL-PreCompiler of the RADIUS Server Stack optimizes during a `RULE_INIT` event the run-time used `$RadSRV(array_label)` names of the RADIUS Server Processors. 

The samples below outlining different Variable Compression Modes of the TCL-PreCompiler and explaining their pros and cons.

# Mode 1: Disable Variable Compression

If you disable the variable compression option within the PreCompiler settings (via `set RadSRV_compiler(compression_enable) 0`), the TCL-PreCompiler won't change the rather long but human friendly `$RadSRV(array_label)` variable names during the `RULE_INIT` event.

The performance of the RADIUS Server Stack will be slightly degrated because the creation, maintenance and lockup of those rather long `$RadSRV(array_label)` variable names requires additional CPU cycles. The benefit of this mode is a simplyfied development and iRule debugging. You will always know what the purpose of those human friendly `$RadSRV(array_label)` variables are - within your code and when a TCL-Stack-Trace happens.  

### Disabled PreCompiler Compression Results:

Below is an uncompressed code snipped fetched from the RADIUS Server Processor.

```
#
#+ Handler for RADIUS request password attribute decryption
#

if { [RADIUS::avp 2] eq "" } then {
} elseif { [string length [RADIUS::avp 2]] == 16 } then {
	binary scan [RADIUS::avp 2] WW RadSRV(encrypted_password_64bit_chunk_1) RadSRV(encrypted_password_64bit_chunk_2)
	binary scan [md5 "$client_config(shared_key)$RadSRV(request_authenticator)"] WW RadSRV(encryption_key_64bit_chunk_1) RadSRV(encryption_key_64bit_chunk_2)
	lappend RadSRV(plaintext_password_64bit_chunks) [expr { $RadSRV(encrypted_password_64bit_chunk_1) ^ $RadSRV(encryption_key_64bit_chunk_1) }] [expr { $RadSRV(encrypted_password_64bit_chunk_2) ^ $RadSRV(encryption_key_64bit_chunk_2) }]
	binary scan [binary format W* $RadSRV(plaintext_password_64bit_chunks)] A* RadSRV(plaintext_password)
	RADIUS::avp replace 2 $RadSRV(plaintext_password)
} elseif { [string length [RADIUS::avp 2]] % 16 == 0 } then {
	binary scan [RADIUS::avp 2] W* RadSRV(encrypted_password_64bit_chunks)
	set RadSRV(encryption_iv) $RadSRV(request_authenticator)
	foreach { RadSRV(encrypted_password_64bit_chunk_1) RadSRV(encrypted_password_64bit_chunk_2) } $RadSRV(encrypted_password_64bit_chunks) {
		binary scan [md5 "$client_config(shared_key)$RadSRV(encryption_iv)"] WW RadSRV(encryption_key_64bit_chunk_1) RadSRV(encryption_key_64bit_chunk_2)
		lappend RadSRV(plaintext_password_64bit_chunks) [expr { $RadSRV(encrypted_password_64bit_chunk_1) ^ $RadSRV(encryption_key_64bit_chunk_1) }] [expr { $RadSRV(encrypted_password_64bit_chunk_2) ^ $RadSRV(encryption_key_64bit_chunk_2) }]
		set RadSRV(encryption_iv) [binary format WW $RadSRV(encrypted_password_64bit_chunk_1) $RadSRV(encrypted_password_64bit_chunk_2)]
	}
	binary scan [binary format W* $RadSRV(plaintext_password_64bit_chunks)] A* RadSRV(plaintext_password)
	RADIUS::avp replace 2 $RadSRV(plaintext_password)
} else {
	RADIUS::avp replace 2 ""
}
```

# Mode 2: Enable Variable Compression with "unique" mappings

If you enable the included variable compression option within the PreCompiler settings (via `set RadSRV_compiler(compression_enable) 1`), the TCL-PreCompiler will change the rather long and human friendly `$RadSRV(array_label)` variable names to shrinked variable names (e.g. `${al}`) during the `RULE_INIT` event. 

The performance of the RADIUS Server Stack will be slightly optimized because the creation, maintenance and lockup of those short variable name requires less CPU cycles and memory. The downside of this mode is a more difficult iRule debugging experience, because the code you write and the executed code is now different. If a TCL stack trace happens, you may need to use the compression map to become able to translate the short run-time varible names back to their long form to spot the problem in the code you write. But in the end this should not a big deal...

### "unique" PreCompiler Compression Map:

The compression map of this mode is sorted in alphabetical order where each human friendly variable is getting trunkated to a short and unique abbreviation. The variable name which are getting exposed to custom iRule solutions (e.g. `client_config()`, `client_response()` and  `session_state()` are not compressed. 

```
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
	"ACCEPT"					"ACCEPT"  	\
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

```

### "unique" PreCompiler Compression Result:

Below is an compressed code snipped fetched from the RADIUS Server Processor. The used compression map was set to "unique".

```
#
#+ Handler for RADIUS request password attribute decryption
#

if { [RADIUS::avp 2] eq "" } then {
} elseif { [string length [RADIUS::avp 2]] == 16 } then {
	binary scan [RADIUS::avp 2] WW {ep641} {ep642}
	binary scan [md5 "$client_config(shared_key)${qa}"] WW {ek641} {ek642}
	lappend {pp64} [expr { ${ep641} ^ ${ek641} }] [expr { ${ep642} ^ ${ek642} }]
	binary scan [binary format W* ${pp64}] A* {pp}
	RADIUS::avp replace 2 ${pp}
} elseif { [string length [RADIUS::avp 2]] % 16 == 0 } then {
	binary scan [RADIUS::avp 2] W* {ep64}
	set {iv} ${qa}
	foreach { {ep641} {ep642} } ${ep64} {
		binary scan [md5 "$client_config(shared_key)${iv}"] WW {ek641} {ek642}
		lappend {pp64} [expr { ${ep641} ^ ${ek641} }] [expr { ${ep642} ^ ${ek642} }]
		set {iv} [binary format WW ${ep641} ${ep642}]
	}
	binary scan [binary format W* ${pp64}] A* {pp}
	RADIUS::avp replace 2 ${pp}
} else {
	RADIUS::avp replace 2 ""
}
```

# Mode 3: Enable Variable Compression with "shared" mappings

You may use the experimental "shared" compression mode by replacing the default "unique" compression map at the bottom of the provided TCL PreCompiler section with a "shared" compression map that optimizes the run-time executed code to its maximum. 

The "shared" compression map consolidates one or more rather long and human friendly `$RadSRV(array_label)` variable names to a combined single letter variable name (e.g. `${1}`) to reduce the total number of variable creations, the required time to lookup a given variable and the memory footprint of all used variables to an absolute minimum.

The downside of this mode is an absolute nightmarish iRule debugging experience. If a TCL stack trace happens and complains problems with lets say variable `${2}` you will most likely not be able to translate those shared variable names back to the rather long and human friendly `$RadSRV(array_label)` original variable name. One or more different `$RadSRV(array_label)` variables may be mapped to the single letter variable name `${2}`. 

### "shared" PreCompiler Compression Map:

The compression map of this mode is generated by reading and analyzing the original code of the RADIUS Server Processor from top to the button. 

Whenever a `$RadSRV(something)` variable is used for the first time, it gets assigned the next free entry of a single letter pool (e.g. `$RadSRV(someting)` becomes `${1}` and `$RadSRV(someting_else)` becomes `${2}`). The usage of such single letter variable names is considered the most CPU and memory friendly choice.  

Whenever a given `$RadSRV(something)` variable is not used anymore till the end of RADIUS Server Processor (aka. it has done its job!), its reserved entry in the single letter pool will get released, so that the very next `$RadSRV(something_different)` variable used for the first time can reuse the already initialized single letter varibale of `${1}`. This approach would eleminate the need to create a new variable for each unique variable usecase (creation of variables costs CPU and Memory) and also immediately free the memory used to hold the now obsolete variable data (costs Memory if variable data remains in the stack longer than needed) without manually releasing it (costs CPU to release the data explicitly via `[unset]`). 

Recycling of varibale names (respectivily their internal memory links within the TCL runtime) is therefor the key to optimize the last nimbles of an already highly optimized TCL code.

```

# Note: The variable names are sorted in the order of appearance and getting compressed to the next free entry of a single letter pool.
#       If the variable is not used anymore, its number will be added back to the pool ready for reuse (cpu savings).
#       If a variable had previously stored large amounts of data, the variable will be reused preferred (memory savings).
#	The variable names a-z are used for shared variables that are used within the Pre- and Post-Processor.  

lappend RadSRV_compiler(replace_map) \
	" \]"						"\]"	\
	RadSRV(request_timestamp)			"{a}"	\
	RadSRV(request_code)				"{1}"	\
	RadSRV(request_id)				"{b}"	\
	RadSRV(request_length)				"{2}"	\
	RadSRV(request_authenticator)			"{c}"	\
	RadSRV(payload_offset)				"{1}"	\
	RadSRV(request_attribute_length)		"{3}"	\
	RadSRV(request_hmac)				"{1}"	\
	RadSRV(request_state_label)			"{d}"	\
	RadSRV(request_state)				"{1}"	\
	RadSRV(x)					"{1}"	\
	RadSRV(response_attributes_field)		"{e}"	\
	RadSRV(session_state_array)			"{1}"	\
	RadSRV(session_state_variable)			"{2}"	\
	RadSRV(session_state_variable_value)		"{3}"	\
	RadSRV(encrypted_password_64bit_chunk_1)	"{1}"	\
	RadSRV(encrypted_password_64bit_chunk_2)	"{2}"	\
	RadSRV(encryption_key_64bit_chunk_1)		"{3}"	\
	RadSRV(encryption_key_64bit_chunk_2)		"{4}"	\
	RadSRV(plaintext_password_64bit_chunks)		"{5}"	\
	RadSRV(encrypted_password_64bit_chunks)		"{6}"	\
	RadSRV(encryption_iv)				"{7}"	\
	RadSRV(plaintext_password)			"{6}"	\
	RadSRV(response_attribute_type) 		"{6}"	\
	RadSRV(response_attribute_format) 		"{5}"	\
	RadSRV(response_attribute_value) 		"{4}"	\
	RadSRV(response_attribute_mask) 		"{3}"	\
	RadSRV(response_length)				"{2}"	\
	RadSRV(response_payload)			"{1}"	\
	tmm(table_iterations)				"{1}"	\
	tmm(start_timestamp)				"{2}"	\
	tmm(stop_timestamp)				"{3}"	\
	tmm(x)						"{4}"	\
	"tmm_times"					"tt"	\
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

```

### "shared" PreCompiler Compression Result:

Below is an compressed code snipped fetched from the RADIUS Server Processor. The used compression map was set to "shared".

```
#
#+ Handler for RADIUS request password attribute decryption
#

if { [RADIUS::avp 2] eq "" } then {
} elseif { [string length [RADIUS::avp 2]] == 16 } then {
	binary scan [RADIUS::avp 2] WW {1} {2}
	binary scan [md5 "$client_config(shared_key)${c}"] WW {3} {4}
	lappend {5} [expr { ${1} ^ ${3} }] [expr { ${2} ^ ${4} }]
	binary scan [binary format W* ${5}] A* {6}
	RADIUS::avp replace 2 ${6}
} elseif { [string length [RADIUS::avp 2]] % 16 == 0 } then {
	binary scan [RADIUS::avp 2] W* {6}
	set {7} ${c}
	foreach { {1} {2} } ${6} {
		binary scan [md5 "$client_config(shared_key)${7}"] WW {3} {4}
		lappend {5} [expr { ${1} ^ ${3} }] [expr { ${2} ^ ${4} }]
		set {7} [binary format WW ${1} ${2}]
	}
	binary scan [binary format W* ${5}] A* {6}
	RADIUS::avp replace 2 ${6}
} else {
	RADIUS::avp replace 2 ""
}
```
