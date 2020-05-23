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

import {Component, OnInit} from '@angular/core';
import {PasswordLoginCredential} from "../auth/password-login-credential";
import {AuthService} from "../auth/auth.service";
import {WebAuthnService} from "../webauthn/web-authn.service";
import {Router} from "@angular/router";
import {Alert} from "../alert/alert";
import * as Bowser from "bowser";

@Component({
  selector: 'app-password-login',
  templateUrl: './password-login.component.html',
  styleUrls: ['./password-login.component.css']
})
export class PasswordLoginComponent implements OnInit {

  private bowser = Bowser.getParser(window.navigator.userAgent);

  alerts: Alert[] = [];

  passwordLoginCredential: PasswordLoginCredential = {
    username: "",
    password: ""
  };
  submitting = false;


  constructor(private authService: AuthService, private router: Router) {
  }

  ngOnInit() {

  }

  loginWithPasswordCredential() {
    this.authService.loginWithPasswordCredential(this.passwordLoginCredential.username, this.passwordLoginCredential.password)
      .subscribe((data: string) => {
        this.router.navigate(["/profile"]);
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

  loginWithPublicKeyCredential() {

    this.authService.loginWithPublicKeyCredential({
      userVerification: "required"
    }).subscribe((data: string) => {
      this.router.navigate(["/profile"]);
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

  isWebAuthnAvailable(): boolean {
    return WebAuthnService.isWebAuthnAvailable();
  }

  isChromeForWindows(): boolean {
    return this.bowser.satisfies({windows: {chrome: '>0'}})
  }

  isChromeForMac(): boolean {
    return this.bowser.satisfies({macos: {chrome: '>0'}})
  }

  isChromeForAndroid(): boolean {
    return this.bowser.satisfies({android: {chrome: '>0'}})
  }

  isChromeForIOS(): boolean {
    return this.bowser.satisfies({ios: {chrome: '>0'}})
  }

  isFirefoxForWindows(): boolean {
    return this.bowser.satisfies({windows: {firefox: '>0'}})
  }

  isFirefoxForMac(): boolean {
    return this.bowser.satisfies({macos: {firefox: '>0'}})
  }

  isFirefoxForAndroid(): boolean {
    return this.bowser.satisfies({android: {firefox: '>0'}})
  }

  isFirefoxForIOS(): boolean {
    return this.bowser.satisfies({ios: {firefox: '>0'}})
  }

  isSafariForMac(): boolean {
    return this.bowser.satisfies({macos: {safari: '>0'}})
  }

  isSafariForIOS(): boolean {
    return this.bowser.satisfies({ios: {safari: '>0'}})
  }

}
