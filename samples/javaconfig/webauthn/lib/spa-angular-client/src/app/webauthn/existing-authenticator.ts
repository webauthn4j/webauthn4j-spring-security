import { Authenticator } from './authenticator';

export class ExistingAuthenticator implements Authenticator{
  id: number;
  credentialId: ArrayBuffer;
  name: string;
}
