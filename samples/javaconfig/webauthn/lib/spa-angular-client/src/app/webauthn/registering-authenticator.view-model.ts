import { AuthenticatorViewModel } from './authenticator.view-model';

export class RegisteringAuthenticatorViewModel implements AuthenticatorViewModel {

  constructor(
    public credentialId: ArrayBuffer,
    public name: string,
    public clientData: ArrayBuffer,
    public attestationObject: ArrayBuffer
  ) {
  }
}


