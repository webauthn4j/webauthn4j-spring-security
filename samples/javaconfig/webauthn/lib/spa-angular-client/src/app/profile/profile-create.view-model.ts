import {AuthenticatorViewModel} from "../webauthn/authenticator.view-model";

export interface ProfileCreateViewModel {
  userHandle: string;
  firstName: string;
  lastName: string;
  emailAddress: string;
  password: string;
  authenticators: AuthenticatorViewModel[];
  singleFactorAuthenticationAllowed: boolean;
}
