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
package dsr.fd.device.ios

import future.keywords.if
import future.keywords.in

import data.ios_data

# METADATA
# description: A rule that checks the 'type' of the DeviceToken.
is_ios_device if {
	input.deviceTokenPayload.type == "IOS"
}

# METADATA
# description: A rule that determines if 'systemModel' is allowed.
system_model_predicate if {
	is_ios_device
	system_model = trim_space(input.deviceTokenPayload.deviceHealth.deviceAttributes.systemModel)
	system_model in ios_data.allowedSystemModels
}

# Generate violation if device systemModel attribut not match
violations[v] {
	is_ios_device
	not system_model_predicate
	v := {
		"errorCode": "device_system_model_not_match",
		"errorDescription": sprintf("iOS: The device system model (%v) is not allowed", [input.deviceTokenPayload.deviceHealth.deviceAttributes.systemModel]),
	}
}

# METADATA
# description: A rule that determines if 'systemVersion' is allowed - check via REGEX
system_version_predicate if {
	is_ios_device
	system_version := trim_space(input.deviceTokenPayload.deviceHealth.deviceAttributes.systemVersion)
	regex.match(`^(17|16)(\.[0-9]+)*$`, system_version)
}

# Generate violation if device systemModel attribut not match
violations[v] {
	is_ios_device
	not system_version_predicate
	v := {
		"errorCode": "device_system_version_not_match",
		"errorDescription": sprintf("iOS: The device system version (%v) is not allowed", [input.deviceTokenPayload.deviceHealth.deviceAttributes.systemVersion]),
	}
}

# METADATA
# description: |
#   A rule that determines if 'rpID' is allowed. The 'rpID' is a hash of your app’s App ID.
rpid_predicate if {
	is_ios_device
	input.deviceTokenPayload.deviceHealth.assertion.rpID in ios_data.allowedRpIDs
}

# Generate violation if device rpID attribut not match
violations[v] {
	is_ios_device
	not rpid_predicate
	v := {
		"errorCode": "device_pq_id_not_match",
		"errorDescription": sprintf("iOS: The hash of your app (%v) does not match", [input.deviceTokenPayload.deviceHealth.assertion.rpID]),
	}
}

# Calculate the final result, all checks must pass
allow if {
	is_ios_device
	system_model_predicate
	system_version_predicate
	rpid_predicate
	count(violations) == 0
}
