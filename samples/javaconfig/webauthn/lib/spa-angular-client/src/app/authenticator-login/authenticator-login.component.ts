import {AfterContentInit, Component, OnInit} from '@angular/core';
import {AuthService} from "../auth/auth.service";
import {WebauthnService} from "../webauthn/webauthn.service";
import {Router} from "@angular/router";
import {Alert} from "../alert/alert";

@Component({
  selector: 'app-authenticator-login',
  templateUrl: './authenticator-login.component.html',
  styleUrls: ['./authenticator-login.component.css']
})
export class AuthenticatorLoginComponent implements OnInit, AfterContentInit {

  alerts: Alert[] = [];

  constructor(private authService: AuthService, private router: Router) { }

  ngOnInit() {
  }

  ngAfterContentInit(){
    this.loginWithPublicKeyCredential();
  }

  loginWithPublicKeyCredential() {

    this.authService.loginWithPublicKeyCredential({
      userVerification: "preferred"
    }).subscribe((data: string) =>{
      this.router.navigate(["profile"]);
    } , (error) =>{
      switch(error.name)
      {
        case "NotAllowedError":
          console.info(error);
          return;
        default:
          console.error(error);
      }
    });
  }

  logout(){
    this.authService.logout()
      .subscribe(
        () => {
          window.location.href = "/";
        }
      );
  }

  isWebAuthnAvailable(): boolean{
    return WebauthnService.isWebAuthnAvailable();
  }

}
