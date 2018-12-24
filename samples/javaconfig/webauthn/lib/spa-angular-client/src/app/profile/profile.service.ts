import {Injectable, OnInit} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {RegisteringAuthenticatorViewModel} from "../webauthn/registering-authenticator.view-model";
import {WebauthnService} from "../webauthn/webauthn.service";
import {Observable} from "rxjs/internal/Observable";
import { base64url } from "rfc4648";
import {ProfileUpdateViewModel} from "./profile-update.view-model";
import {ProfileViewModel} from "./profile.view-model";
import {ProfileCreateViewModel} from "./profile-create.view-model";
import {v4 as uuid} from "uuid";
import {AuthenticatorViewModel} from "../webauthn/authenticator.view-model";
import {ProfileForm} from "./profile.form";
import {AuthenticatorForm} from "./authenticator.form";
import {RegisteringAuthenticatorForm} from "./registering-authenticator.form";
import {ExistingAuthenticatorForm} from "./existing-authenticator.form";
import {ExistingAuthenticatorViewModel} from "../webauthn/existing-authenticator.view-model";
import {map} from "rxjs/operators";
import {UserForm} from "../user/user.form";

@Injectable({
  providedIn: 'root'
})
export class ProfileService implements OnInit {

  private profileUrl: string = "/api/profile";

  constructor(private webauthnService: WebauthnService, private http: HttpClient) { }

  ngOnInit(): void {
  }

  createCredential(
    userHandleBase64: string,
    username: string,
    displayName: string,
    credentialIds: ArrayBuffer[],
    requireResidentKey: boolean
  ): Promise<Credential> {
    let userHandle = base64url.parse(userHandleBase64, { loose: true });
    let excludeCredentials: PublicKeyCredentialDescriptor[] = credentialIds.map(credentialId => {
      // noinspection UnnecessaryLocalVariableJS
      let credential: PublicKeyCredentialDescriptor = {type: "public-key", id: credentialId};
      return credential;
    });
    return this.webauthnService.createCredential({
      user: {
        id: userHandle,
        name: username,
        displayName: displayName
      },
      excludeCredentials: excludeCredentials,
      authenticatorSelection: {
        requireResidentKey: requireResidentKey
      },
      attestation: "direct"
    });
  }

  create(profile: ProfileCreateViewModel): Observable<ProfileViewModel> {
    let profileForm: ProfileForm = {
      userHandle: uuid().toString(),
      firstName: profile.firstName,
      lastName: profile.lastName,
      emailAddress: profile.emailAddress,
      password: profile.password,
      authenticators: profile.authenticators.map(authenticator => {
        return this.mapToAuthenticatorForm(authenticator);
      }),
      singleFactorAuthenticationAllowed: profile.singleFactorAuthenticationAllowed
    };
    return this.http.post<ProfileViewModel>(this.profileUrl, profileForm);
  }

  update(profile: ProfileUpdateViewModel): Observable<ProfileViewModel> {
    let data = {
      userHandle: profile.userHandle,
      emailAddress: profile.emailAddress,
      firstName: profile.firstName,
      lastName: profile.lastName,
      authenticators: profile.authenticators.map(authenticator => {
        return this.mapToAuthenticatorForm(authenticator);
      }),
      singleFactorAuthenticationAllowed: profile.singleFactorAuthenticationAllowed
    };
    return this.http.put<ProfileViewModel>(this.profileUrl, data);
  }

  load(): Observable<ProfileViewModel> {
    return this.http.get<ProfileForm>(this.profileUrl).pipe(map((userForm: UserForm) => {
      return {
        userHandle: userForm.userHandle,
        firstName: userForm.firstName,
        lastName: userForm.lastName,
        emailAddress: userForm.emailAddress,
        password: userForm.password,
        authenticators:  userForm.authenticators.map(authenticator => this.mapToAuthenticatorViewModel(authenticator)),
        singleFactorAuthenticationAllowed: userForm.singleFactorAuthenticationAllowed
      };
    }));
  }

  remove(): Observable<void> {
    return this.http.delete<void>(this.profileUrl);
  }

  private mapToAuthenticatorViewModel(authenticatorForm: AuthenticatorForm): AuthenticatorViewModel{
    if((<RegisteringAuthenticatorForm>authenticatorForm).clientData && (<RegisteringAuthenticatorForm>authenticatorForm).attestationObject){
      let registeringAuthenticator: RegisteringAuthenticatorViewModel = {
        name: authenticatorForm.name,
        credentialId: base64url.parse(authenticatorForm.credentialId, { loose: true }).buffer,
        clientData: base64url.parse((<RegisteringAuthenticatorForm>authenticatorForm).clientData, { loose: true }).buffer,
        attestationObject: base64url.parse((<RegisteringAuthenticatorForm>authenticatorForm).attestationObject, { loose: true }).buffer,
        clientExtensionsJSON: (<RegisteringAuthenticatorForm>authenticatorForm).clientExtensionsJSON
      };
      return registeringAuthenticator;
    }
    else if((<ExistingAuthenticatorForm>authenticatorForm).id){
      let existingAuthenticator: ExistingAuthenticatorViewModel = {
        id: (<ExistingAuthenticatorForm>authenticatorForm).id,
        name: authenticatorForm.name,
        credentialId: base64url.parse(authenticatorForm.credentialId, { loose: true }).buffer
      };
      return existingAuthenticator;
    }
    else {
      throw new Error("Unexpected Authenticator type is provided");
    }
  }

  private mapToAuthenticatorForm(authenticator: AuthenticatorViewModel): AuthenticatorForm {
    if((<RegisteringAuthenticatorViewModel>authenticator).clientData && (<RegisteringAuthenticatorViewModel>authenticator).attestationObject){
      let registeringAuthenticatorForm: RegisteringAuthenticatorForm = {
        name: authenticator.name,
        credentialId: base64url.stringify(new Uint8Array(authenticator.credentialId)),
        clientData: base64url.stringify(new Uint8Array((<RegisteringAuthenticatorViewModel>authenticator).clientData)),
        attestationObject: base64url.stringify(new Uint8Array((<RegisteringAuthenticatorViewModel>authenticator).attestationObject)),
        clientExtensionsJSON: (<RegisteringAuthenticatorViewModel>authenticator).clientExtensionsJSON
      };
      return registeringAuthenticatorForm;
    }
    else if((<ExistingAuthenticatorViewModel>authenticator).id){
      let existingAuthenticatorForm: ExistingAuthenticatorForm = {
        id: (<ExistingAuthenticatorViewModel>authenticator).id,
        name: authenticator.name,
        credentialId: base64url.stringify(authenticator.credentialId)
      };
      return existingAuthenticatorForm;
    }
    else {
      throw new Error("Unexpected Authenticator type is provided");
    }
  }
}
