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
import {Observable} from "rxjs/internal/Observable";
import {AttestationOptionsResponse} from "./attestation-options-response";
import {AssertionOptionsResponse} from "./assertion-options-response";
import * as Bowser from "bowser";
import {map} from "rxjs/operators";

@Injectable({
  providedIn: 'root'
})
export class WebAuthnService {

  private static bowser = Bowser.getParser(window.navigator.userAgent);

  private _attestationOptionsUrl: string = "/webauthn/attestation/options";
  private _assertionOptionsUrl: string = "/webauthn/assertion/options";

  constructor(private httpClient: HttpClient) {
  }

  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NgCredentialCreationOptions
  );
  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NgCredentialCreationOptions, serverOptions: AttestationServerOptions
  );
  createCredential(
    webAuthnCredentialCreationOptions: WebAuthn4NgCredentialCreationOptions, serverOptions?: AttestationServerOptions
  ): Promise<Credential> {
    let serverOptionsPromise: Promise<AttestationServerOptions>;
    if (serverOptions === undefined) {
      serverOptionsPromise = this.fetchAttestationServerOptions().toPromise()
    } else {
      serverOptionsPromise = Promise.resolve(serverOptions);
    }

    return serverOptionsPromise.then(serverOptions => {

      let timeout: number;
      if (typeof webAuthnCredentialCreationOptions.timeout != "undefined" && webAuthnCredentialCreationOptions.timeout != null) {
        timeout = webAuthnCredentialCreationOptions.timeout;
      } else if (typeof serverOptions.timeout != "undefined" && serverOptions.timeout != null) {
        timeout = serverOptions.timeout;
      } else {
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
    webAuthnCredentialRequestOptions: WebAuthn4NgCredentialRequestOptions
  );
  getCredential(
    webAuthnCredentialRequestOptions: WebAuthn4NgCredentialRequestOptions, serverOptions: AssertionServerOptions
  );
  getCredential(
    webAuthnCredentialRequestOptions: WebAuthn4NgCredentialRequestOptions, serverOptions?: AssertionServerOptions
  ): Promise<Credential> {
    let serverOptionsPromise: Promise<AssertionServerOptions>;
    if (serverOptions === undefined) {
      serverOptionsPromise = this.fetchAssertionServerOptions().toPromise();
    } else {
      serverOptionsPromise = Promise.resolve(serverOptions);
    }

    return serverOptionsPromise.then(serverOptions => {

      let timeout: number;
      if (typeof webAuthnCredentialRequestOptions.timeout != "undefined" && webAuthnCredentialRequestOptions.timeout != null) {
        timeout = webAuthnCredentialRequestOptions.timeout;
      } else if (typeof serverOptions.timeout != "undefined" && serverOptions.timeout != null) {
        timeout = serverOptions.timeout;
      } else {
        timeout = undefined;
      }

      let publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: webAuthnCredentialRequestOptions.challenge ? webAuthnCredentialRequestOptions.challenge : serverOptions.challenge,
        timeout: timeout,
        rpId: webAuthnCredentialRequestOptions.rpId ? webAuthnCredentialRequestOptions.rpId : serverOptions.rpId,
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


  fetchAttestationServerOptions(): Observable<AttestationServerOptions> {
    return this.httpClient.get<AttestationOptionsResponse>(this._attestationOptionsUrl).pipe(map<AttestationOptionsResponse, AttestationServerOptions>(response => {
      return {
        relyingParty: response.relyingParty,
        user: response.user,
        challenge: base64url.decodeBase64url(response.challenge),
        pubKeyCredParams: response.pubKeyCredParams,
        timeout: response.timeout,
        credentials: response.credentials.map(credential => {
          return {
            type: credential.type,
            id: base64url.decodeBase64url(credential.id),
            //TODO: transports: credential.transports
          }
        })
      };
    }));
  }

  fetchAssertionServerOptions(): Observable<AssertionServerOptions> {
    return this.httpClient.get<AssertionOptionsResponse>(this._assertionOptionsUrl).pipe(map<AssertionOptionsResponse, AssertionServerOptions>(response => {
      return {
        challenge: base64url.decodeBase64url(response.challenge),
        pubKeyCredParams: response.pubKeyCredParams,
        timeout: response.timeout,
        rpId: response.rpId,
        credentials: response.credentials.map(credential => {
          return {
            type: credential.type,
            id: base64url.decodeBase64url(credential.id),
            //TODO: transports: credential.transports
          }
        }),
        parameters: response.parameters
      };
    }));
  }

  get attestationOptionsUrl(): string {
    return this._attestationOptionsUrl;
  }

  set attestationOptionsUrl(value: string) {
    this._attestationOptionsUrl = value;
  }

  static isWebAuthnAvailable(): boolean {
    let untypedWindow: any = window;
    return navigator.credentials && untypedWindow.PublicKeyCredential;
  }

  static isResidentKeyLoginAvailable(): boolean {
    return WebAuthnService.isWebAuthnAvailable() &&
      this.bowser.satisfies({windows: {chrome: '>118.01.1322'}});
  }
}
