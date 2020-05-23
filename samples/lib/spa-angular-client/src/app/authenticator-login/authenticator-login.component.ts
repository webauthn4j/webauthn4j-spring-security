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

import {AfterContentInit, Component, OnInit} from '@angular/core';
import {AuthService} from "../auth/auth.service";
import {WebAuthnService} from "../webauthn/web-authn.service";
import {Router} from "@angular/router";
import {Alert} from "../alert/alert";

@Component({
  selector: 'app-authenticator-login',
  templateUrl: './authenticator-login.component.html',
  styleUrls: ['./authenticator-login.component.css']
})
export class AuthenticatorLoginComponent implements OnInit, AfterContentInit {

  alerts: Alert[] = [];
  submitting = false;

  constructor(private authService: AuthService, private router: Router) {
  }

  ngOnInit() {
  }

  ngAfterContentInit() {
    this.loginWithPublicKeyCredential();
  }

  loginWithPublicKeyCredential() {

    this.authService.loginWithPublicKeyCredential({
      userVerification: "preferred"
    }).subscribe((data: string) => {
      this.router.navigate(["profile"]);
    }, (error) => {
      let alert: Alert;
      switch (error.name) {
        case "NotAllowedError":
          console.info(error);
          return;
        case "HttpErrorResponse":
          alert = {
            type: "danger",
            message: "Authentication failed"
          };
          this.alerts = [alert];
          return;
        default:
          alert = {
            type: "danger",
            message: "Authentication failed with " + error.name
          };
          this.alerts = [alert];
          return;
      }
    });
  }

  logout() {
    this.authService.logout()
      .subscribe(
        () => {
          window.location.href = "/";
        }
      );
  }

  isWebAuthnAvailable(): boolean {
    return WebAuthnService.isWebAuthnAvailable();
  }

}
