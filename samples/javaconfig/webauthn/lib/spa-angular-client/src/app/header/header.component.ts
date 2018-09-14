import { Component, OnInit } from '@angular/core';
import {AuthService} from "../auth/auth.service";
import {AuthenticationStatus} from "../auth/authentication-status";
import {Router} from "@angular/router";

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit {

  constructor(private authService: AuthService, private router: Router) {
    router.events.subscribe(event => {
      this.authService.getAuthenticationStatus().subscribe( authStatus =>{
        this.authStatus = authStatus;
      });
    });
  }

  authStatus: AuthenticationStatus = "Anonymous";

  ngOnInit() {}

  logout(){
    this.authService.logout()
      .subscribe(
        () => {
          window.location.href = "/";
        }
      );
  }

}
