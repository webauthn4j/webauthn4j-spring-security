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

import {Injectable} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import * as base64url from "../webauthn/base64url";
import {WebAuthnService} from "../webauthn/web-authn.service";
import {Observable} from "rxjs/internal/Observable";
import {from} from 'rxjs';
import {concatMap, map} from 'rxjs/operators';
import {throwError} from "rxjs/internal/observable/throwError";
import {WebAuthn4NgCredentialRequestOptions} from "../webauthn/web-authn-4-ng-credential-request-options";
import {AuthResponse} from "./auth-response";
import {AuthenticationStatus} from "./authentication-status";

@Injectable({
  providedIn: 'root',
})
export class AuthService {

  private loginUrl: string = "/login";
  private webAuthnLoginUrl: string = "/webAuthnLogin";
  private logoutUrl: string = "/logout";
  private authStatusUrl: string = "/api/auth/status";

  constructor(private webauthnService: WebAuthnService, private http: HttpClient) {
  }


  loginWithPublicKeyCredential(credentialRequestOptions: WebAuthn4NgCredentialRequestOptions): Observable<string> {
    let promise = this.webauthnService.fetchAssertionServerOptions().toPromise().then((serverOptions) => {
      return this.webauthnService.getCredential(credentialRequestOptions, serverOptions).then(credential => {
        return {serverOptions: serverOptions, credential: credential}
      });
    });

    return from(promise).pipe(concatMap((data) => {
      if (data.credential.type != "public-key") {
        throwError("Unexpected credential type");
      }
      let publicKeyCredential: PublicKeyCredential = data.credential as PublicKeyCredential;
      let assertionResponse: AuthenticatorAssertionResponse = publicKeyCredential.response as AuthenticatorAssertionResponse;
      let clientDataJSON = assertionResponse.clientDataJSON;
      let authenticatorData = assertionResponse.authenticatorData;
      let signature = assertionResponse.signature;
      // let clientExtensions = publicKeyCredential.getClientExtensionResults(); //Edge preview throws exception as of build 180603-1447
      let clientExtensions = {};

      if (publicKeyCredential.response as AuthenticatorAttestationResponse) {
        let formData = new FormData();
        formData.set(data.serverOptions.parameters.credentialId, base64url.encodeBase64url(new Uint8Array(publicKeyCredential.rawId)));
        formData.set(data.serverOptions.parameters.clientDataJSON, base64url.encodeBase64url(new Uint8Array(clientDataJSON)));
        formData.set(data.serverOptions.parameters.authenticatorData, base64url.encodeBase64url(new Uint8Array(authenticatorData)));
        formData.set(data.serverOptions.parameters.signature, base64url.encodeBase64url(new Uint8Array(signature)));

        return this.http.post(this.webAuthnLoginUrl, formData, {responseType: 'text'});
      }
    }));
  }

  loginWithPasswordCredential(username: string, password: string): Observable<string> {
    let data = new FormData();
    data.set('username', username);
    data.set('password', password);

    return this.http.post(this.loginUrl, data, {responseType: 'text'});
  }

  logout(): Observable<string> {
    return this.http.post(this.logoutUrl, null, {responseType: 'text'});
  }

  getAuthenticationStatus(): Observable<AuthenticationStatus> {
    return this.http.get<AuthResponse>(this.authStatusUrl).pipe(map<AuthResponse, AuthenticationStatus>(response => response.status));
  }


}
