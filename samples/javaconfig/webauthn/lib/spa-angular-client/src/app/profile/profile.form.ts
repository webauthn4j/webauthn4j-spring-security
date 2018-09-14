import {AuthenticatorForm} from "./authenticator.form";

export interface ProfileForm {
  userHandle: string;
  firstName: string;
  lastName: string;
  emailAddress: string;
  password: string;
  authenticators: AuthenticatorForm[];
  singleFactorAuthenticationAllowed: boolean;
}
