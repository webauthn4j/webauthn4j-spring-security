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
import {RegisteringAuthenticatorViewModel} from "../webauthn/registering-authenticator.view-model";
import {WebAuthnService} from "../webauthn/web-authn.service";
import {AuthenticatorDialogComponent} from "../authenticator-dialog/authenticator-dialog.component";
import {Router} from "@angular/router";
import {NgbModal} from "@ng-bootstrap/ng-bootstrap";
import {AuthenticatorRegistrationReconfirmationDialogComponent} from "../authenticator-registration-reconfirmation-dialog/authenticator-registration-reconfirmation-dialog.component";
import {Alert} from "../alert/alert";
import {ProfileService} from "./profile.service";
import {ProfileUpdateViewModel} from "./profile-update.view-model";
import {ResidentKeyRequirementDialogComponent} from "../resident-key-requirement-dialog/resident-key-requirement-dialog.component";
import {AuthService} from "../auth/auth.service";

@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {

  constructor(
    private profileService: ProfileService,
    private authService: AuthService,
    private router: Router,
    private modalService: NgbModal) {
  }

  ngOnInit() {
    this.profileService.load().subscribe((user) => {
      this.user.userHandle = user.userHandle;
      this.user.firstName = user.firstName;
      this.user.lastName = user.lastName;
      this.user.emailAddress = user.emailAddress;
      this.user.authenticators = user.authenticators;
      this.user.singleFactorAuthenticationAllowed = user.singleFactorAuthenticationAllowed;
    });
    this.checkUVPAA().then((isUVPAA) => {
      this.isUVPAA = isUVPAA;
    });
  }

  isUVPAA: boolean = false;

  submitting = false;

  alerts: Alert[] = [];

  user: ProfileUpdateViewModel = {
    userHandle: "",
    firstName: "",
    lastName: "",
    emailAddress: "",
    authenticators: [],
    singleFactorAuthenticationAllowed: false
  };

  addAuthenticator() {

    this.checkResidentKeyRequirement().then(residentKeyRequirement => {
      let credentialIds = this.user.authenticators.map(authenticator => authenticator.credentialId);
      this.profileService.createCredential(this.user.userHandle, this.user.emailAddress, this.user.emailAddress, credentialIds, residentKeyRequirement)
        .then(credential => {
          if (credential.type != "public-key") {
            Promise.reject("Unexpected credential type");
          }
          let publicKeyCredential: PublicKeyCredential = credential as PublicKeyCredential;
          let attestationResponse: AuthenticatorAttestationResponse = publicKeyCredential.response as AuthenticatorAttestationResponse;
          let clientData = attestationResponse.clientDataJSON;
          let attestationObject = attestationResponse.attestationObject;
          // let clientExtensions = credential.getClientExtensionResults(); //Edge preview throws exception as of build 180603-1447
          let clientExtensions = {};
          let clientExtensionsJSON = JSON.stringify(clientExtensions);

          let name = "Authenticator";

          let authenticator = new RegisteringAuthenticatorViewModel(publicKeyCredential.rawId, name, clientData, attestationObject, clientExtensionsJSON);
          this.user.authenticators.push(authenticator);

          this.alerts = [];
          return Promise.resolve();
        }).catch(exception => {
        let message: string;
        switch (exception.name) {
          case "NotAllowedError":
            console.info(exception);
            return;
          case "InvalidStateError":
            message = "The authenticator is already registered.";
            break;
          default:
            message = "Unexpected error is thrown.";
            console.error(exception);
        }
        let alert: Alert = {
          type: "danger",
          message: message
        };
        this.alerts = [alert];
      });
    }, () => {
    });
  }

  editAuthenticator(authenticator) {
    let modal = this.modalService.open(AuthenticatorDialogComponent);
    let component = modal.componentInstance;
    component.authenticator = {name: authenticator.name};
    modal.result.then(() => {
      authenticator.name = component.authenticator.name;
    });
  }


  removeAuthenticator(authenticator) {
    this.user.authenticators.splice(this.user.authenticators.indexOf(authenticator), 1);
  }

  update() {
    this.reconfirmAuthenticatorRegistration().then(result => {
      if (result) {
        this.addAuthenticator();
      } else {
        this.submitting = true;
        this.profileService.update(this.user)
          .subscribe(
            () => {
              let message = "Profile update finished.";
              let alert: Alert = {
                type: "info",
                message: message
              };
              this.alerts = [alert];
              this.submitting = false;
            },
            (error) => {
              let message = "Profile update failed.";
              let alert: Alert = {
                type: "danger",
                message: message
              };
              this.alerts = [alert];
              this.submitting = false;
              console.error(error);
            }
          );
      }
    });
  }

  checkUVPAA(): Promise<boolean> {
    let untypedWindow: any = window;
    return untypedWindow.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }

  checkResidentKeyRequirement(): Promise<boolean> {
    return this.modalService.open(ResidentKeyRequirementDialogComponent, {centered: true}).result;
  }

  reconfirmAuthenticatorRegistration(): Promise<boolean> {
    if (this.user.authenticators.length == 0 && this.isUVPAA) {
      return this.modalService.open(AuthenticatorRegistrationReconfirmationDialogComponent, {centered: true}).result;
    }
    return Promise.resolve(false);
  }

  isWebAuthnAvailable(): boolean {
    return WebAuthnService.isWebAuthnAvailable();
  }


}
