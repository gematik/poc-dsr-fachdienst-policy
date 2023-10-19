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

package dsr.fd.security.policy_test

import data.dsr.fd.security

import future.keywords.if

security_test_data := {
    "blocklistClientIPs": ["217.110.27.221"],
    "blocklistUserIdentifier": ["TEST", "X-TEST"],
    "torExitNodes": ["101.36.105.41"],
    "allowedCountryCodes": ["SE"]
    }

test_security_allowed if {
	security.allow
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "217.110.27.113",
		"countryCode": "SE"
	}}
		with data.security_data as security_test_data
}

test_security_client_ip_blocked_not_allow if {
	not security.allow
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "217.110.27.221",
		"countryCode": "SE"
	}}
		with data.security_data as security_test_data
}

test_security_client_ip_blocked_violations if {
	count(security.violations) == 1
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "217.110.27.221",
		"countryCode": "SE"
	}}
		with data.security_data as security_test_data
}

test_security_country_code_not_allow if {
	not security.allow
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "217.110.17.112",
		"countryCode": "XX"
	}}
		with data.security_data as security_test_data
}

test_security_country_code_violations if {
	count(security.violations) == 1
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "217.110.17.112",
		"countryCode": "XX"
	}}
		with data.security_data as security_test_data
}

test_security_tor_client_ip_not_allow if {
	not security.allow
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "101.36.105.41",
		"countryCode": "SE"
	}}
		with data.security_data as security_test_data
}

test_security_tor_client_ip_violations if {
	count(security.violations) == 1
	with input as {"request": {
		"method": "GET",
		"path": "/api/v1/notfalldaten",
		"clientIP": "101.36.105.41",
		"countryCode": "SE"
	}}
		with data.security_data as security_test_data
}

test_security_user_not_allow if {
	not security.allow
	with input as {"request": {
        "method": "GET",
        "path": "/api/v1/notfalldaten",
        "clientIP": "217.110.27.113",
        "countryCode": "SE"
        },
        "deviceTokenValid": true,
        "deviceTokenPayload": {
            "type": "IOS",
            "userIdentifier": "TEST"
        }
	}
		with data.security_data as security_test_data
}

test_security_user_violations if {
	count(security.violations) == 1
	with input as {"request": {
        "method": "GET",
        "path": "/api/v1/notfalldaten",
        "clientIP": "217.110.27.113",
        "countryCode": "SE"
        },
        "deviceTokenValid": true,
        "deviceTokenPayload": {
            "type": "IOS",
            "userIdentifier": "X-TEST"
        }
	}
		with data.security_data as security_test_data
}
