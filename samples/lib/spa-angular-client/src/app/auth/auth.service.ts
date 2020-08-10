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
  private logoutUrl: string = "/logout";
  private authStatusUrl: string = "/api/auth/status";

  constructor(private webauthnService: WebAuthnService, private http: HttpClient) {
  }


  loginWithPublicKeyCredential(credentialRequestOptions: WebAuthn4NgCredentialRequestOptions): Observable<string> {
    let promise = this.webauthnService.getCredential(credentialRequestOptions);

    return from(promise).pipe(concatMap((credential) => {
      if (credential.type != "public-key") {
        throwError("Unexpected credential type");
      }
      let publicKeyCredential: PublicKeyCredential = credential as PublicKeyCredential;
      let assertionResponse: AuthenticatorAssertionResponse = publicKeyCredential.response as AuthenticatorAssertionResponse;
      let clientDataJSON = assertionResponse.clientDataJSON;
      let authenticatorData = assertionResponse.authenticatorData;
      let signature = assertionResponse.signature;
      let clientExtensions = publicKeyCredential.getClientExtensionResults();

      if (publicKeyCredential.response as AuthenticatorAttestationResponse) {
        let formData = new FormData();
        formData.set("credentialId", base64url.encodeBase64url(new Uint8Array(publicKeyCredential.rawId)));
        formData.set("clientDataJSON", base64url.encodeBase64url(new Uint8Array(clientDataJSON)));
        formData.set("authenticatorData", base64url.encodeBase64url(new Uint8Array(authenticatorData)));
        formData.set("signature", base64url.encodeBase64url(new Uint8Array(signature)));
        formData.set("clientExtensionsJSON", JSON.stringify(clientExtensions));

        return this.http.post(this.loginUrl, formData, {responseType: 'text'});
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
