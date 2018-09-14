import {AuthenticatorViewModel} from "../webauthn/authenticator.view-model";

export interface ProfileUpdateViewModel {
  userHandle: string;
  firstName: string;
  lastName: string;
  emailAddress: string;
  authenticators: AuthenticatorViewModel[];
  singleFactorAuthenticationAllowed: boolean;
}
