export interface ServerOptions {
  relyingParty: PublicKeyCredentialRpEntity;
  challenge: BufferSource;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number,
  credentials: PublicKeyCredentialDescriptor[];
  parameters: {
    username: string,
    password: string,
    credentialId: string,
    clientDataJSON: string,
    authenticatorData: string,
    signature: string,
    clientExtensionsJSON: string
  };
}

