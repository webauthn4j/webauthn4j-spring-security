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

import {ProfileComponent} from './profile.component';
import {FormsModule} from "@angular/forms";
import {NgbAlertModule} from "@ng-bootstrap/ng-bootstrap";
import {of} from "rxjs/internal/observable/of";
import {AuthService} from "../auth/auth.service";
import {ProfileService} from "./profile.service";
import {RouterTestingModule} from "@angular/router/testing";
import {ProfileViewModel} from "./profile.view-model";

describe('ProfileComponent', () => {
  let component: ProfileComponent;
  let fixture: ComponentFixture<ProfileComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [ProfileComponent],
      imports: [
        FormsModule,
        NgbAlertModule,
        RouterTestingModule
      ]
    }).overrideComponent(ProfileComponent, {
      set: {
        providers: [
          {
            provide: AuthService,
            useFactory: () => {
              let authServiceMock = new AuthService(null, null);
              spyOn(authServiceMock, "getAuthenticationStatus").and.returnValue(of("NOT_AUTHENTICATED"));
              return authServiceMock;
            }
          },
          {
            provide: ProfileService,
            useFactory: () => {
              let profileServiceMock = new ProfileService(null, null);
              let profile: ProfileViewModel = {
                userHandle: "",
                emailAddress: "",
                firstName: "",
                lastName: "",
                authenticators: [],
                singleFactorAuthenticationAllowed: false
              };
              spyOn(profileServiceMock, "load").and.returnValue(of(profile));
              return profileServiceMock;
            }
          }

        ]
      }
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ProfileComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
