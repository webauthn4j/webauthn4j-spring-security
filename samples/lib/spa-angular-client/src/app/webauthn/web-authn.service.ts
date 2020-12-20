/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// <reference types="webappsec-credential-management" />
// DO NOT REMOVE: The above comment is mandatory to use webappsec-credential-management type definition

import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import * as base64url from "./base64url";
import {WebAuthn4NgCredentialCreationOptions} from "./web-authn-4-ng-credential-creation-options";
import {WebAuthn4NgCredentialRequestOptions} from "./web-authn-4-ng-credential-request-options";
import {AttestationServerOptions} from "./attestation-server-options";
import {AssertionServerOptions} from "./assertion-server-options";
import * as Bowser from "bowser";

@Injectable({
  providedIn: 'root'
})
export class WebAuthnService {

  private static bowser = Bowser.getParser(window.navigator.userAgent);

  private _attestationOptionsUrl: string = "/webauthn/attestation/options";
  private _assertionOptionsUrl: string = "/webauthn/assertion/options";

  constructor(private httpClient: HttpClient) {
  }

  createCredential(publicKeyCredentialCreationOptions: WebAuthn4NgCredentialCreationOptions): Promise<Credential> {
    return this.fetchAttestationOptions().then(fetchedOptions => {

      let mergedOptions = { ...fetchedOptions, ...publicKeyCredentialCreationOptions};

      let credentialCreationOptions: CredentialCreationOptions = {
        publicKey: mergedOptions
      };

      return navigator.credentials.create(credentialCreationOptions);
    });
  }

  getCredential(publicKeyCredentialRequestOptions: WebAuthn4NgCredentialRequestOptions): Promise<Credential> {
    return this.fetchAssertionOptions().then(fetchedOptions => {

      let mergedOptions = { ...fetchedOptions, ...publicKeyCredentialRequestOptions};

      let credentialRequestOptions: CredentialRequestOptions = {
        publicKey: mergedOptions
      };

      return navigator.credentials.get(credentialRequestOptions);
    });
  }

  fetchAttestationOptions(): Promise<PublicKeyCredentialCreationOptions> {
    return this.httpClient.get<AttestationServerOptions>(this._attestationOptionsUrl).toPromise().then(serverOptions => {
      return {
        rp: serverOptions.rp,
        user: serverOptions.user ? {
          id: base64url.decodeBase64url(serverOptions.user.id),
          name: serverOptions.user.name,
          displayName: serverOptions.user.displayName
        } : null,
        challenge: base64url.decodeBase64url(serverOptions.challenge),
        pubKeyCredParams: serverOptions.pubKeyCredParams,
        timeout: serverOptions.timeout,
        excludeCredentials: serverOptions.excludeCredentials ? serverOptions.excludeCredentials.map(credential => {
          return {
            type: credential.type,
            id: base64url.decodeBase64url(credential.id),
            transports: credential.transports
          }
        }): null,
        authenticatorSelection: serverOptions.authenticatorSelection,
        attestation: serverOptions.attestation,
        extensions: serverOptions.extensions
      };
    });
  }

  fetchAssertionOptions(): Promise<PublicKeyCredentialRequestOptions> {
    return this.httpClient.get<AssertionServerOptions>(this._assertionOptionsUrl).toPromise().then(serverOptions => {
      return {
        challenge: base64url.decodeBase64url(serverOptions.challenge),
        timeout: serverOptions.timeout,
        rpId: serverOptions.rpId,
        allowCredentials: serverOptions.allowCredentials ? serverOptions.allowCredentials.map(credential => {
          return {
            type: credential.type,
            id: base64url.decodeBase64url(credential.id),
            transports: credential.transports
          }
        }) : null,
        userVerification: serverOptions.userVerification,
        extensions: serverOptions.extensions
      };
    });
  }

  static isWebAuthnAvailable(): boolean {
    return true;
    // let untypedWindow: any = window;
    // return navigator.credentials && untypedWindow.PublicKeyCredential;
  }

  static isResidentKeyLoginAvailable(): boolean {
    return WebAuthnService.isWebAuthnAvailable() &&
      this.bowser.satisfies({windows: {chrome: '>118.01.1322'}});
  }
}
