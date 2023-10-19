#
# Copyright 2023 gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# METADATA
# scope: package
package dsr.fd.security

import future.keywords.if
import future.keywords.in

import data.security_data

# METADATA
# description: A rule that determines if client IP is blocked.
blocked_client_ip if {
	input.request.clientIP in security_data.blocklistClientIPs
} else = false

# Generate security violation if client IP is on the IP blocklist.
violations[v] {
	blocked_client_ip
	v := {
		"errorCode": "request_client_ip_blocked",
		"errorDescription": sprintf("Security: The request client IP (%v) is blocked", [input.request.clientIP])
	}
}

# METADATA
# description: A rule that determines if 'countryCode' from client IP is allowed.
country_code_allowed if {
	input.request.countryCode in security_data.allowedCountryCodes
} else = false

# Generate violation if request country code attribut not match
violations[v] {
	not country_code_allowed
	v := {
		"errorCode": "request_country_code_not_match",
		"errorDescription": sprintf("Security: The country code (%v) determined from the client IP is not allowed", [input.request.countryCode]),
	}
}

# METADATA
# description: A rule that determines if client IP is on the TOR exit node list.
tor_listed_client_ip if {
	input.request.clientIP in security_data.torExitNodes
} else = false

# Generate security violation if client IP is on the TOR exit node list.
violations[v] {
	tor_listed_client_ip
	v := {
		"errorCode": "request_client_ip_not_allowed",
		"errorDescription": sprintf("Security: The request client IP (%v) is not allowed, because the IP was found at the TOR exit node list", [input.request.clientIP])
	}
}

# METADATA
# description: A rule that determines if user (Device-Token 'userIdentifier') is blocked.
blocked_user_identifier if {
	input.deviceTokenPayload.userIdentifier in security_data.blocklistUserIdentifier
} else = false

# Generate security violation if client IP is on the IP blocklist.
violations[v] {
	blocked_user_identifier
	v := {
		"errorCode": "user_identifier_not_allowed",
		"errorDescription": sprintf("Security: The userIdentifier '%v' is blocked", [input.deviceTokenPayload.userIdentifier])
	}
}

# Calculate the final result, all checks must pass
allow if {
	not blocked_client_ip
	country_code_allowed
	not tor_listed_client_ip
	not blocked_user_identifier
	count(violations) == 0
} else = false
