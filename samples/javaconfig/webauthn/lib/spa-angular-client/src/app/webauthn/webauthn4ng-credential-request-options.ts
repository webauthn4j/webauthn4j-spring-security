export interface WebAuthn4NGCredentialRequestOptions {
  challenge?: BufferSource;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptor[];
  userVerification?: UserVerificationRequirement;
  extensions?: any;
}
