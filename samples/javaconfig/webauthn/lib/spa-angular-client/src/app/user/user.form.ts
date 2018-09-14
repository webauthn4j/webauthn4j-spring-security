import {AuthenticatorForm} from "../profile/authenticator.form";

export interface UserForm {
  id: number;
  userHandle: string;
  firstName: string;
  lastName: string;
  emailAddress: string;
  password: string;
  authenticators: AuthenticatorForm[];
  singleFactorAuthenticationAllowed: boolean;
}
