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
package dsr.fd.device.android

import future.keywords.if
import future.keywords.in

import data.android_data

# METADATA
# description: A rule that checks the 'type' of the DeviceToken.
is_android_device if {
	input.deviceTokenPayload.type == "ANDROID"
}

# METADATA
# description: |
#   A rule that checks the app integrity values 'packageName', 'versionCode' and 'certificateSha256Digest'.
allowed_application_predicate if {
    is_android_device
	input_package_name = trim_space(input.deviceTokenPayload.deviceHealth.integrityVerdict.appIntegrity.packageName)
	input_version = input.deviceTokenPayload.deviceHealth.integrityVerdict.appIntegrity.versionCode
	input_certificate_sha256_digest := input.deviceTokenPayload.deviceHealth.integrityVerdict.appIntegrity.certificateSha256Digest[0]

	some application in android_data.allowedApplications
	application == {
		"packageName": input_package_name,
		"version": input_version,
		"certificateSha256Digest": input_certificate_sha256_digest
	}
} else = false

# Generate violation if application not match.
violations[v] {
	is_android_device
	not allowed_application_predicate
	v := {
		"errorCode": "device_application_not_match",
		"errorDescription": sprintf("Android: The application '%v' version: %v is not allowed",
		    [input.deviceTokenPayload.deviceHealth.integrityVerdict.appIntegrity.packageName,
		    input.deviceTokenPayload.deviceHealth.integrityVerdict.appIntegrity.versionCode])
	}
}

# METADATA
# description: A rule that determines if 'build.model' is allowed.
build_model_predicate if {
	is_android_device
	buildModel = input.deviceTokenPayload.deviceHealth.deviceAttributes.build.model
	buildModel in android_data.allowedBuildModel
}

# Generate violation if device build.model attribut not match.
violations[v] {
	is_android_device
	not build_model_predicate
	v := {
		"errorCode": "device_system_model_not_match",
		"errorDescription": sprintf("Android: The device build model (%v) is not allowed", [input.deviceTokenPayload.deviceHealth.deviceAttributes.build.model]),
	}
}

# METADATA
# description: A rule that determines if 'SecurityLevel of attestation' is allowed.
#  SOFTWARE             = 0
#  TRUSTED_ENVIRONMENT  = 1
#  STRONG_BOX           = 2
attestation_security_level_predicate if {
	is_android_device
	input.deviceTokenPayload.deviceHealth.keyIdAttestation.attestationSecurityLevel in [1, 2]
}

# Generate violation if device 'SecurityLevel of attestation' not match.
violations[v] {
	is_android_device
	not attestation_security_level_predicate
	v := {
		"errorCode": "device_attestation_security_level_not_match",
		"errorDescription": sprintf("Android: The SecurityLevel of attestation (%v) is not allowed", [input.deviceTokenPayload.deviceHealth.keyIdAttestation.attestationSecurityLevel]),
	}
}

# See if device has minimum required patch level
MINIMUM_SECURITY_PATCH_LEVEL := android_data.minimumSecurityPatchLevel

# METADATA
# description: A rule that determines if 'build.version.securityPatch' is allowed.
build_version_security_patch_predicate {
  is_android_device
  input.deviceTokenPayload.deviceHealth.deviceAttributes.build.version.securityPatch >= MINIMUM_SECURITY_PATCH_LEVEL
}

# Generate violation if device securityPatch attribut not match.
violations[v] {
  is_android_device
  not build_version_security_patch_predicate
  v := {
    "errorCode": "device_build_version_security_patch_violation",
    "errorDescription": sprintf("Android: Device is required to have securityPatch level %s or higher. Current patch level: %s.", [MINIMUM_SECURITY_PATCH_LEVEL, input.deviceTokenPayload.deviceHealth.deviceAttributes.build.version.securityPatch])
  }
}

# METADATA
# description: A rule that determines if 'passwordComplexity' is allowed.
#  PASSWORD_COMPLEXITY_HIGH     = 327680
#  PASSWORD_COMPLEXITY_MEDIUM   = 196608
#  PASSWORD_COMPLEXITY_LOW      = 65536
#  PASSWORD_COMPLEXITY_NONE     = 0
password_complexity_predicate if {
	is_android_device
	input.deviceTokenPayload.deviceHealth.deviceAttributes.devicePolicyManager.passwordComplexity in [327680, 196608]
}

# Generate violation if device passwordComplexity attribut not match.
violations[v] {
	is_android_device
	not password_complexity_predicate
	v := {
		"errorCode": "device_password_complexity_not_match",
		"errorDescription": sprintf("Android: The device passwordComplexity (%v) is not allowed", [input.deviceTokenPayload.deviceHealth.deviceAttributes.devicePolicyManager.passwordComplexity]),
	}
}

# Calculate the final result, all checks must pass.
allow if {
	is_android_device
	allowed_application_predicate
	build_model_predicate
	attestation_security_level_predicate
	build_version_security_patch_predicate
	password_complexity_predicate
	count(violations) == 0
}