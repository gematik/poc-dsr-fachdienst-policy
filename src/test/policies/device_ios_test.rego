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

package dsr.fd.device.ios_test

import data.dsr.fd.device.ios

import future.keywords.if

ios_test_data := {
	"allowedSystemModels": [
		"iPhone13,3",
		"iPhone14,3",
		"iPhone15,3",
		"iPhone16,1"
	],
	"allowedSystemVersions": [
		"16.6",
		"16.5.1",
		"17.0.2"
	],
	"allowedRpIDs": ["8/FR27wyIIXITNLSkepN9neNcVG+gAKVL0k89/FEGlY"]
}

test_device_ios_allowed if {
	ios.allow with input as {"deviceTokenPayload": {
		"type": "IOS",
		"userIdentifier": "X114428530",
		"deviceHealth": {
			"assertion": {
				"counter": 1,
				"rpID": "8/FR27wyIIXITNLSkepN9neNcVG+gAKVL0k89/FEGlY",
				"riskMetric": "unavailable",
			},
			"deviceAttributes": {
				"systemVersion": "16.6",
				"systemName": "iOS",
				"identifierForVendor": "E065D0D8-0382-4BF0-BA73-27C1C3E6BC9E",
				"systemModel": "iPhone13,3",
			},
		},
		"iss": "DSR GMS 1.0.0",
		"sub": "N2Q7vrEKuiJb6uYWMtr9jHqTkmIBk4M1dyPc1PxSUJ8=",
		"iat": 1694174674,
		"exp": 1694178274,
		"cnf": {"x5t#S256": "7UDk5HhpjDg9fL-Z6bwZXCU6z45UiSBS52nUHXNiOKI"},
		"jti": "4cdbe2cb-e1a7-4bcc-ada8-14b0357a33b4",
	}}
		with data.ios_data as ios_test_data
}

test_device_ios_invalid_systemVersion if {
	not ios.allow
	count(ios.violations) == 1 with input as {"deviceTokenPayload": {
		"type": "IOS",
		"userIdentifier": "TEST KVNR",
		"deviceHealth": {
			"assertion": {
				"counter": 1,
				"rpID": "8/FR27wyIIXITNLSkepN9neNcVG+gAKVL0k89/FEGlY",
				"riskMetric": "unavailable",
			},
			"deviceAttributes": {
				"systemVersion": "iOS unknown",
				"systemName": "iOS",
				"identifierForVendor": "B8C94B1C-1FC9-4B2D-B9BF-9F94A534BFA1",
				"systemModel": "iPhone15,3",
			},
		},
	}}
		with data.ios_data as ios_test_data
}

test_device_ios_invalid_systemModel if {
	not ios.allow
	count(ios.violations) == 1 with input as {"deviceTokenPayload": {
		"type": "IOS",
		"userIdentifier": "TEST KVNR",
		"deviceHealth": {
			"assertion": {
				"counter": 1,
				"rpID": "8/FR27wyIIXITNLSkepN9neNcVG+gAKVL0k89/FEGlY",
				"riskMetric": "unavailable",
			},
			"deviceAttributes": {
				"systemVersion": "16.5.1",
				"systemName": "iOS",
				"identifierForVendor": "B8C94B1C-1FC9-4B2D-B9BF-9F94A534BFA1",
				"systemModel": "iPhone unkown",
			},
		},
	}}
		with data.ios_data as ios_test_data
}

test_device_ios_invalid_rpID if {
	not ios.allow
	count(ios.violations) == 1 with input as {"deviceTokenPayload": {
		"type": "IOS",
		"userIdentifier": "TEST KVNR",
		"deviceHealth": {
			"assertion": {
				"counter": 1,
				"rpID": "Hello-TEST",
				"riskMetric": "unavailable",
			},
			"deviceAttributes": {
				"systemVersion": "17.0.2",
				"systemName": "iOS",
				"identifierForVendor": "B8C94B1C-1FC9-4B2D-B9BF-9F94A534BFA1",
				"systemModel": "iPhone16,1"
			},
		},
	}}
		with data.ios_data as ios_test_data
}

test_device_ios_invalid_type if {
	not ios.allow
	count(ios.violations) == 0 with input as {"deviceTokenPayload": {
		"type": "unknown"
	}}
}
