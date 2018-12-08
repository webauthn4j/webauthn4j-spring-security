import { Component, OnInit } from '@angular/core';
import {PasswordLoginCredential} from "../auth/password-login-credential";
import {AuthService} from "../auth/auth.service";
import {WebauthnService} from "../webauthn/webauthn.service";
import {Router} from "@angular/router";
import {Alert} from "../alert/alert";

@Component({
  selector: 'app-password-login',
  templateUrl: './password-login.component.html',
  styleUrls: ['./password-login.component.css']
})
export class PasswordLoginComponent implements OnInit {

  alerts: Alert[] = [];

  passwordLoginCredential: PasswordLoginCredential = {
    username: "",
    password: ""
  };

  constructor(private authService: AuthService, private router: Router) { }

  ngOnInit() {

  }

  loginWithPasswordCredential(){
    this.authService.loginWithPasswordCredential(this.passwordLoginCredential.username, this.passwordLoginCredential.password)
      .subscribe((data: string) =>{
        this.router.navigate(["/profile"]);
      }, (error) =>{
        let alert: Alert;
        switch(error.name)
        {
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

    // As of 2018-11-25, Firefox doesn't support password-less login, but it ignores userVerification option.
    if(this.authService.isFirefox()){
      let message = "Firefox doesn't support device login (password-less login). Firefox only supports two-step login."
        + " For two-step login, you need to press 'Login' button instead of 'Device Login' button.";
      let alert: Alert = {
        type: "danger",
        message: message
      };
      this.alerts = [alert];
      return;
    }

    this.authService.loginWithPublicKeyCredential({
      userVerification: "required"
    }).subscribe((data: string) =>{
      this.router.navigate(["/profile"]);
    }, (error) =>{
      let alert: Alert;
      switch(error.name)
      {
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

  isWebAuthnAvailable(): boolean{
    return WebauthnService.isWebAuthnAvailable();
  }

}
