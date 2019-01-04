import {AuthenticatorViewModel} from './authenticator.view-model';

export class ExistingAuthenticatorViewModel implements AuthenticatorViewModel{
  id: number;
  credentialId: ArrayBuffer;
  name: string;
}
