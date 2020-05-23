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
import {AuthService} from "../auth/auth.service";
import {AuthenticationStatus} from "../auth/authentication-status";
import {Router} from "@angular/router";

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  authStatus: AuthenticationStatus = "NOT_AUTHENTICATED";

  constructor(private authService: AuthService, private router: Router) {
    router.events.subscribe(_ => {
      this.authService.getAuthenticationStatus().subscribe(authStatus => {
        this.authStatus = authStatus;
      });
    });
  }

  ngOnInit() {
  }


}
