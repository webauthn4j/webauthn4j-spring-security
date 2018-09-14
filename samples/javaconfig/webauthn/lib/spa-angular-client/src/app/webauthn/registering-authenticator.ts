import { Authenticator } from './authenticator';

export class RegisteringAuthenticator implements Authenticator {

  constructor(
    public credentialId: ArrayBuffer,
    public name: string,
    public clientData: ArrayBuffer,
    public attestationObject: ArrayBuffer
  ) {
  }
}


