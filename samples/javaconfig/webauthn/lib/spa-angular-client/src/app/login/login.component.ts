import { Component, OnInit } from '@angular/core';
import {AuthService} from "../auth/auth.service";
import {AuthenticationStatus} from "../auth/authentication-status";
import {Router} from "@angular/router";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  authStatus: AuthenticationStatus = "Anonymous";

  constructor(private authService: AuthService, private router: Router) {
    router.events.subscribe(_ => {
      this.authService.getAuthenticationStatus().subscribe( authStatus =>{
        this.authStatus = authStatus;
      });
    });
  }

  ngOnInit() {
  }



}
