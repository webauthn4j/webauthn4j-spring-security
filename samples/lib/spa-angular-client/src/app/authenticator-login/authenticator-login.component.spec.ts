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

import { ComponentFixture, TestBed, waitForAsync } from '@angular/core/testing';

import {AuthenticatorLoginComponent} from './authenticator-login.component';
import {NgbAlertModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";
import {AuthService} from "../auth/auth.service";
import {of} from "rxjs/internal/observable/of";
import {RouterTestingModule} from "@angular/router/testing";
import {ProfileComponent} from "../profile/profile.component";

describe('AuthenticatorLoginComponent', () => {
  let component: AuthenticatorLoginComponent;
  let fixture: ComponentFixture<AuthenticatorLoginComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [
        AuthenticatorLoginComponent,
        ProfileComponent
      ],
      imports: [
        NgbAlertModule,
        FormsModule,
        RouterTestingModule.withRoutes([
          {path: 'profile', component: ProfileComponent},
        ])
      ]
    }).overrideComponent(AuthenticatorLoginComponent, {
      set: {
        providers: [
          {
            provide: AuthService,
            useFactory: () => {
              let authServiceMock = new AuthService(null, null);
              spyOn(authServiceMock, "loginWithPublicKeyCredential").and.returnValue(of(""));
              spyOn(authServiceMock, "getAuthenticationStatus").and.returnValue(of("NOT_AUTHENTICATED"));
              return authServiceMock;
            }
          }
        ]
      }
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AuthenticatorLoginComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
