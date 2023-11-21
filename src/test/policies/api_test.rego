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

package dsr.fd.api_test

import data.dsr.fd.api as api

import future.keywords.if

ios_test_data := {
	"allowedSystemModels": ["iPhone13,3", "iPhone13,2"],
	"allowedRpIDs": ["8/FR27wyIIXITNLSkepN9neNcVG+gAKVL0k89/FEGlY"]
}

android_test_data := {
    "allowedBuildModel": [
	    "Pixel 6",
	    "Pixel 7"
    ],
    "allowedApplications": [
        {
            "packageName": "de.gematik.dsr.android",
            "version": 1,
            "certificateSha256Digest": "Br8MmBmVeijVKv77d2_UxosqaKD0F2IyTJ-Ak04IhBI"
        }
    ],
    "minimumSecurityPatchLevel": "2023-01-01"
  }

security_test_data := {
    "blocklistClientIPs": ["217.110.27.123"],
    "allowedCountryCodes": ["DE"]
    }

test_api_ios_allowed if {
	api.verdict.allow with input as {
		"request": {
			"method": "GET",
			"path": "api/v1/notfalldaten",
			"clientIP": "217.110.27.113",
			"countryCode": "DE"
		},
		"deviceTokenValid": true,
		"deviceTokenPayload": {
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
		},
	}
		with data.ios_data as ios_test_data
		with data.security_data as security_test_data
}

test_api_android_allowed if {
	api.verdict.allow with input as {
		"request": {
			"method": "GET",
			"path": "api/v1/notfalldaten",
			"clientIP": "217.110.27.113",
			"countryCode": "DE"
		},
		"deviceTokenValid": true,
		"deviceTokenPayload": {
			"type": "ANDROID",
			"userIdentifier": "TEST KVNR",
			"deviceHealth": {
				"integrityVerdict": {
					"appIntegrity": {
						"appRecognitionVerdict": "UNRECOGNIZED_VERSION",
						"packageName": "de.gematik.dsr.android",
						"certificateSha256Digest": ["Br8MmBmVeijVKv77d2_UxosqaKD0F2IyTJ-Ak04IhBI"],
						"versionCode": 1
					},
					"deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
					"accountDetails": {"appLicensingVerdict": "UNLICENSED"},
				},
				"keyIdAttestation": {
					"attestationVersion": 200,
					"attestationSecurityLevel": 1,
					"softwareEnforced": {
						"creationDateTime": "2023-07-24T10:59:02.933Z",
						"usageExpireDateTime": "2024-07-23T12:59:02Z",
						"activeDateTime": "2023-07-24T09:59:02Z",
						"attestationApplicationId": {
							"packageInfos": [{
								"packageName": "de.gematik.dsr.android",
								"version": 1
							}],
							"signatureDigests": ["Br8MmBmVeijVKv77d2/UxosqaKD0F2IyTJ+Ak04IhBI="],
						},
						"rootOfTrust": null,
						"originationExpireDateTime": "2024-07-23T12:59:02Z",
					},
					"teeEnforced": {
						"purpose": [
							2,
							3,
						],
						"attestationIdDevice": "b3Jpb2xl",
						"keySize": 256,
						"osVersion": 130000,
						"origin": 0,
						"osPatchLevel": 202306,
						"attestationIdModel": "UGl4ZWwgNg==",
						"attestationIdProduct": "b3Jpb2xl",
						"vendorPatchLevel": 20230605,
						"attestationApplicationId": null,
						"noAuthRequired": true,
						"rootOfTrust": {
							"verifiedBootKey": "D251yAGDtd7AdLAFTUJx6ZOJ6+SxNrCBneHxULoP+dc=",
							"deviceLocked": true,
							"verifiedBootState": "VERIFIED",
							"verifiedBootHash": "fJJjq2OCj8MtUcx328N87IoC7UiRKrEP1DqMuK/7QX0=",
						},
						"algorithm": 3,
						"digest": [4],
						"ecCurve": 1,
						"attestationIdManufacturer": "R29vZ2xl",
						"attestationIdBrand": "Z29vZ2xl",
						"bootPatchLevel": 20230605,
					},
					"keyStore": {
						"type": "KEY_MINT",
						"version": 200,
						"securityLevel": 1,
					},
				},
				"deviceAttributes": {
					"build": {
						"version": {
							"sdkInit": 33,
							"securityPatch": "2023-06-05",
						},
						"manufacturer": "Google",
						"product": "oriole",
						"model": "Pixel 6",
						"board": "oriole",
					},
					"ro": {
						"crypto": {"state": true},
						"product": {"firstAPILevel": 31},
					},
					"packageManager": {"featureVerifiedBoot": true},
					"keyguardManager": {"isDeviceSecure": true},
					"biometricManager": {
						"deviceCredential": true,
						"biometricStrong": true,
					},
					"devicePolicyManager": {"passwordComplexity": 327680},
				},
			},
			"iss": "DSR GMS 1.0.0",
			"sub": "5lxRGYCGmCLahCErhwccUcQDhSmZkBAQhl/cGD7kzEs=",
			"iat": 1693896580,
			"exp": 1693900180,
			"cnf": {"x5t#S256": "7UDk5HhpjDg9fL-Z6bwZXCU6z45UiSBS52nUHXNiOKI"},
			"jti": "67d7503e-d981-443c-998a-679f15f6ac80",
		},
	}
		with data.android_data as android_test_data
		with data.security_data as security_test_data
}

test_api_deviceToken_invalid if {
	not api.verdict.allow
	count(api.violations) == 1 with input as {
		"request": {
			"method": "GET",
			"path": "api/v1/notfalldaten",
			"clientIP": "217.110.27.113"
		},
		"deviceTokenValid": false,
	}
		with data.ios_data as ios_test_data
		with data.security_data as security_test_data
}

test_api_ios_invalid if {
	not api.verdict.allow with input as {
		"request": {
			"method": "GET",
			"path": "api/v1/notfalldaten",
			"clientIP": "217.110.27.101"
		},
		"deviceTokenValid": true,
		"deviceTokenPayload": {
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
					"systemModel": "iPhone 7411",
				},
			},
			"iss": "DSR GMS 1.0.0",
			"sub": "N2Q7vrEKuiJb6uYWMtr9jHqTkmIBk4M1dyPc1PxSUJ8=",
			"iat": 1694174674,
			"exp": 1694178274,
			"cnf": {"x5t#S256": "7UDk5HhpjDg9fL-Z6bwZXCU6z45UiSBS52nUHXNiOKI"},
			"jti": "4cdbe2cb-e1a7-4bcc-ada8-14b0357a33b4",
		},
	}
		with data.ios_data as ios_test_data
		with data.security_data as security_test_data
}

test_api_request_client_ip_blocked if {
	not api.verdict.allow
	count(api.verdict.security.violations) == 1
	with input as {
		"request": {
			"method": "GET",
			"path": "api/v1/notfalldaten",
			"clientIP": "217.110.27.123"
		},
		"deviceTokenValid": true,
		"deviceTokenPayload": {
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
					"systemModel": "iPhone13,2",
				},
			},
			"iss": "DSR GMS 1.0.0",
			"sub": "N2Q7vrEKuiJb6uYWMtr9jHqTkmIBk4M1dyPc1PxSUJ8=",
			"iat": 1694174674,
			"exp": 1694178274,
			"cnf": {"x5t#S256": "7UDk5HhpjDg9fL-Z6bwZXCU6z45UiSBS52nUHXNiOKI"},
			"jti": "4cdbe2cb-e1a7-4bcc-ada8-14b0357a33b4",
		},
	}
		with data.ios_data as ios_test_data
		with data.security_data as security_test_data
}
