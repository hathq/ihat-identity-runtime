use crate::{
    AuthenticationContext, AuthenticationOperation, DeviceEnrollment, DeviceEnrollmentPurpose,
    EvidenceKind, RotateDeviceKeyRequest, RuntimeError,
};

use super::IdentityRuntime;

impl IdentityRuntime {
    pub(crate) fn verify_enrollment_evidence(
        &self,
        request: &DeviceEnrollment,
        operation: AuthenticationOperation,
    ) -> Result<(), RuntimeError> {
        let purpose = match operation {
            AuthenticationOperation::DeviceRecovery => DeviceEnrollmentPurpose::RecoveryReplacement,
            _ => DeviceEnrollmentPurpose::Enrollment,
        };
        self.verify_authentication(
            &request.user_authentication,
            AuthenticationContext {
                operation,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: Some(&request.service_id),
                device_id: Some(&request.device_id),
                external_identity: None,
            },
        )?;
        self.verify_optional_window(
            EvidenceKind::DeviceAttestation,
            self.trust.attestation.verify_enrollment(request, purpose),
        )?;
        self.verify_optional_window(
            EvidenceKind::DeviceKeyPossession,
            self.trust.possession.verify_enrollment(request, purpose),
        )
    }

    pub(crate) fn verify_rotation_evidence(
        &self,
        request: &RotateDeviceKeyRequest,
    ) -> Result<(), RuntimeError> {
        let authentication = request
            .fresh_user_authentication
            .as_ref()
            .ok_or(RuntimeError::FreshAuthenticationRequired)?;
        self.verify_authentication(
            authentication,
            AuthenticationContext {
                operation: AuthenticationOperation::DeviceKeyRotation,
                command_id: &request.command_id,
                account_id: &request.account_id,
                service_id: Some(&request.service_id),
                device_id: Some(&request.device_id),
                external_identity: None,
            },
        )?;
        self.verify_optional_window(
            EvidenceKind::DeviceAttestation,
            self.trust.attestation.verify_rotation(request),
        )?;
        self.verify_optional_window(
            EvidenceKind::DeviceKeyPossession,
            self.trust.possession.verify_rotation(request),
        )
    }
}
