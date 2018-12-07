import {Component, OnInit} from '@angular/core';
import {ProfileCreateViewModel} from "../profile/profile-create.view-model";
import {RegisteringAuthenticatorViewModel} from "../webauthn/registering-authenticator.view-model";
import {Alert} from "../alert/alert";
import { Router } from '@angular/router';
import {NgbModal} from "@ng-bootstrap/ng-bootstrap";
import {AuthenticatorDialogComponent} from "../authenticator-dialog/authenticator-dialog.component";
import {AuthenticatorRegistrationReconfirmationDialogComponent} from "../authenticator-registration-reconfirmation-dialog/authenticator-registration-reconfirmation-dialog.component";
import {WebauthnService} from "../webauthn/webauthn.service";
import {ProfileService} from "../profile/profile.service";
import {v4 as uuid} from "uuid";
import {ResidentKeyRequirementDialogComponent} from "../resident-key-requirement-dialog/resident-key-requirement-dialog.component";

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.css']
})
export class SignupComponent implements OnInit {

  constructor(private profileService: ProfileService, private router: Router, private modalService: NgbModal) { }

  ngOnInit() {
    this.checkUVPAA().then((isUVPAA)=>{
      this.isUVPAA = isUVPAA;
    });
  }

  isUVPAA: boolean = false;

  submitting = false;

  alerts: Alert[] = [];

  user: ProfileCreateViewModel = {
    userHandle: uuid(),
    firstName: "",
    lastName: "",
    emailAddress: "",
    password: "",
    authenticators: [],
    singleFactorAuthenticationAllowed: false
  };

  addAuthenticator() {

    this.checkResidentKeyRequirement().then(residentKeyRequirement =>{
      let credentialIds = this.user.authenticators.map(authenticator => authenticator.credentialId);
      this.profileService.createCredential(this.user.userHandle, this.user.emailAddress, this.user.emailAddress, credentialIds, residentKeyRequirement)
        .then( credential => {
          if(credential.type != "public-key"){
            Promise.reject("Unexpected credential type");
          }
          let publicKeyCredential: PublicKeyCredential = credential as PublicKeyCredential;
          let attestationResponse: AuthenticatorAttestationResponse = publicKeyCredential.response as AuthenticatorAttestationResponse;
          let clientData = attestationResponse.clientDataJSON;
          let attestationObject = attestationResponse.attestationObject;
          //let clientExtensions = credential.getClientExtensionResults(); //Edge preview throws exception as of build 180603-1447
          let clientExtensions = {};
          let clientExtensionsJSON = JSON.stringify(clientExtensions);

          let name = "Authenticator";

          let authenticator = new RegisteringAuthenticatorViewModel(publicKeyCredential.rawId, name, clientData, attestationObject, clientExtensionsJSON);
          this.user.authenticators.push(authenticator);

          this.alerts = [];
          return Promise.resolve();
        }).catch(exception =>{
        let message: string;
        switch(exception.name)
        {
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
    }, ()=>{});
  }

  editAuthenticator(authenticator){
    let modal = this.modalService.open(AuthenticatorDialogComponent);
    let component = modal.componentInstance;
    component.authenticator = {name: authenticator.name};
    modal.result.then( () => {
      authenticator.name = component.authenticator.name;
    });
  }


  removeAuthenticator(authenticator){
    this.user.authenticators.splice(this.user.authenticators.indexOf(authenticator),1);
  }

  signup(){
    this.reconfirmAuthenticatorRegistration().then(result =>{
      if(result){
        this.addAuthenticator();
      }
      else {
        this.submitting = true;
        this.profileService.create(this.user)
          .subscribe(
            () => {
              this.router.navigate(["/"]);
            },
            (error) => {
              let message = "Signup failed.";
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

  checkUVPAA(): Promise<boolean>{
    let untypedWindow: any = window;
    return untypedWindow.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }

  checkResidentKeyRequirement(): Promise<boolean>{
    return this.modalService.open(ResidentKeyRequirementDialogComponent, { centered: true }).result;
  }

  reconfirmAuthenticatorRegistration(): Promise<boolean>{
    if(this.user.authenticators.length == 0 && this.isUVPAA){
      return this.modalService.open(AuthenticatorRegistrationReconfirmationDialogComponent, { centered: true }).result;
    }
    return Promise.resolve(false);
  }

  isWebAuthnAvailable(): boolean{
    return WebauthnService.isWebAuthnAvailable();
  }
}
