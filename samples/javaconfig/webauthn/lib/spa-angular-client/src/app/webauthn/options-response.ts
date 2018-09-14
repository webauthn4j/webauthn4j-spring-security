export interface OptionsResponse {
  relyingParty: PublicKeyCredentialRpEntity;
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  credentials: {
    type: PublicKeyCredentialType;
    id: string;
  }[];
  parameters: {
    username: string,
    password: string,
    credentialId: string,
    clientData: string,
    authenticatorData: string,
    signature: string,
    clientExtensionsJSON: string
  };
}
