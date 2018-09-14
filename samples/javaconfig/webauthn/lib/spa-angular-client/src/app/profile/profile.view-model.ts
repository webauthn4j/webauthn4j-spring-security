import {AuthenticatorViewModel} from "../webauthn/authenticator.view-model";

export interface ProfileViewModel {
  userHandle: string;
  firstName: string;
  lastName: string;
  emailAddress: string;
  authenticators: AuthenticatorViewModel[];
  singleFactorAuthenticationAllowed: boolean;
}
