import {AuthenticatorForm} from "./authenticator.form";

export interface RegisteringAuthenticatorForm extends AuthenticatorForm{
  clientData: string;
  attestationObject: string;
}
