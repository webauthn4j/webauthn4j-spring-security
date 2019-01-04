/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/// <reference types="webappsec-credential-management" />
// DO NOT REMOVE: The above comment is mandatory to use webappsec-credential-management type definition

import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {base64url} from "rfc4648";
import {WebAuthn4NGCredentialCreationOptions} from "./webauthn4ng-credential-creation-options";
import {WebAuthn4NGCredentialRequestOptions} from "./webauthn4ng-credential-request-options";
import {ServerOptions} from "./server-options";
import {Observable} from "rxjs/internal/Observable";
import {OptionsResponse} from "./options-response";
import {map} from "rxjs/operators";

@Injectable({
  providedIn: 'root'
})
export class WebauthnService {

  private _optionsUrl: string = "/webauthn/options";

  constructor(private httpClient: HttpClient) {}

  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NGCredentialCreationOptions
  );
  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NGCredentialCreationOptions, serverOptions: ServerOptions
  );
  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NGCredentialCreationOptions, serverOptions?: ServerOptions
  ): Promise<Credential> {
    let serverOptionsPromise: Promise<ServerOptions>;
    if(serverOptions === undefined){
      serverOptionsPromise = this.fetchServerOptions().toPromise()
    }
    else {
      serverOptionsPromise = Promise.resolve(serverOptions);
    }

    return serverOptionsPromise.then(serverOptions => {

      let timeout: number;
      if(typeof webAuthnCredentialCreationOptions.timeout != "undefined"){
        timeout = webAuthnCredentialCreationOptions.timeout;
      }
      else if(typeof serverOptions.timeout != "undefined"){
        timeout = serverOptions.timeout;
      }
      else {
        timeout = undefined;
      }

      let publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        rp: webAuthnCredentialCreationOptions.rp ? webAuthnCredentialCreationOptions.rp : serverOptions.relyingParty,
        user: webAuthnCredentialCreationOptions.user,
        challenge: webAuthnCredentialCreationOptions.challenge ? webAuthnCredentialCreationOptions.challenge : serverOptions.challenge,
        pubKeyCredParams: webAuthnCredentialCreationOptions.pubKeyCredParams ? webAuthnCredentialCreationOptions.pubKeyCredParams : serverOptions.pubKeyCredParams,
        timeout: timeout,
        excludeCredentials: webAuthnCredentialCreationOptions.excludeCredentials ? webAuthnCredentialCreationOptions.excludeCredentials : serverOptions.credentials,
        authenticatorSelection: webAuthnCredentialCreationOptions.authenticatorSelection,
        attestation: webAuthnCredentialCreationOptions.attestation,
        extensions: webAuthnCredentialCreationOptions.extensions
      };

      let credentialCreationOptions: CredentialCreationOptions = {
        publicKey: publicKeyCredentialCreationOptions
      };

      return navigator.credentials.create(credentialCreationOptions);
    });
  }

  getCredential(
    webAuthnCredentialRequestOptions: WebAuthn4NGCredentialRequestOptions
  );
  getCredential(
    webAuthnCredentialRequestOptions: WebAuthn4NGCredentialRequestOptions, serverOptions: ServerOptions
  );
  getCredential(
    webAuthnCredentialRequestOptions: WebAuthn4NGCredentialRequestOptions, serverOptions?: ServerOptions
  ): Promise<Credential> {
    let serverOptionsPromise: Promise<ServerOptions>;
    if(serverOptions === undefined){
      serverOptionsPromise = this.fetchServerOptions().toPromise();
    }
    else {
      serverOptionsPromise = Promise.resolve(serverOptions);
    }

    return serverOptionsPromise.then(serverOptions => {

      let publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: webAuthnCredentialRequestOptions.challenge ? webAuthnCredentialRequestOptions.challenge : serverOptions.challenge,
        timeout: webAuthnCredentialRequestOptions.timeout,
        rpId: webAuthnCredentialRequestOptions.rpId ? webAuthnCredentialRequestOptions.rpId : serverOptions.relyingParty.id,
        allowCredentials: webAuthnCredentialRequestOptions.allowCredentials ? webAuthnCredentialRequestOptions.allowCredentials : serverOptions.credentials,
        userVerification: webAuthnCredentialRequestOptions.userVerification ? webAuthnCredentialRequestOptions.userVerification : "preferred",
        extensions: webAuthnCredentialRequestOptions.extensions
      };

      let credentialRequestOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };

      return navigator.credentials.get(credentialRequestOptions);
    });
  }


  fetchServerOptions(): Observable<ServerOptions>{
    return this.httpClient.get<OptionsResponse>(this._optionsUrl).pipe(map<OptionsResponse, ServerOptions>(response => {
      return {
        relyingParty: response.relyingParty,
        challenge: base64url.parse(response.challenge, { loose: true }),
        pubKeyCredParams: response.pubKeyCredParams,
        credentials: response.credentials.map(credential => {
          return {
            type: credential.type,
            id: base64url.parse(credential.id, { loose: true })
          }
        }),
        parameters: response.parameters
      };
    }));
  }

  get optionsUrl(): string {
    return this._optionsUrl;
  }

  set optionsUrl(value: string) {
    this._optionsUrl = value;
  }

  static isWebAuthnAvailable(): boolean{
    let untypedWindow: any = window;
    return navigator.credentials && untypedWindow.PublicKeyCredential;
  }
}
