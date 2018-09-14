export interface WebAuthn4NGCredentialCreationOptions {
  rp?: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntity;
  challenge?: BufferSource;
  pubKeyCredParams?: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptor[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: any;
}

