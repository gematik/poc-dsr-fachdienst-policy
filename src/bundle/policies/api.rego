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
# title: OPA policies for DSR Fachdienst API
package dsr.fd.api

import data.dsr.fd.security as securityPolicies
import data.dsr.fd.device.ios as iosPolicies
import data.dsr.fd.device.android as androidPolicies

import future.keywords.if
import future.keywords.in

# By default, deny requests
default allow := false

# Check if DeviceToken is valid
is_device_token_valid if {
	input.deviceTokenValid == true
}

# Generate violation: if DeviceToken is invalid
violations[v] {
	not is_device_token_valid
	v := {
		"errorCode": "device_token_invalid",
		"errorDescription": "The DeviceToken is invalid",
	}
}

# The request must be explicitly allowed by plattform specific security policies
allow_request := securityPolicies.allow

security_violations := securityPolicies.violations

# The device must be explicitly allowed by plattform specific device policies
default allow_device = false

# Allow device (if it is an iOS device and meets the requirements)
allow_device if {
	iosPolicies.allow
}

# Allow device (if it is an Android device meets the requirements)
allow_device if {
	androidPolicies.allow
}

# If device is disallowed, then collect violations
default device_violations = []

# Violations if iOS device
device_violations := iosPolicies.violations if {
	iosPolicies.is_ios_device
}

# Violations if Android device
device_violations := androidPolicies.violations if {
	androidPolicies.is_android_device
}

# Calculate final result, all rules must pass
allow if {
	is_device_token_valid
	allow_request
	allow_device
	count(violations) == 0
	count(security_violations) == 0
	count(device_violations) == 0
}

# Produce the verdict based on all rules and violations
verdict := {
	"allow": allow,
	"device": {
		"allow": allow_device,
		"violations": device_violations
	},
	"security": {
		"allow": allow_request,
		"violations": security_violations
	}
}
