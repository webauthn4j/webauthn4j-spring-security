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

import {SignupComponent} from './signup.component';
import {NgbAlertModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";
import {ProfileService} from "../profile/profile.service";
import {RouterTestingModule} from "@angular/router/testing";
import {AuthService} from "../auth/auth.service";

describe('SignupComponent', () => {
  let component: SignupComponent;
  let fixture: ComponentFixture<SignupComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [SignupComponent],
      imports: [
        NgbAlertModule,
        FormsModule,
        RouterTestingModule
      ]
    }).overrideComponent(SignupComponent, {
      set: {
        providers: [
          {
            provide: ProfileService,
            useFactory: () => {
              return new ProfileService(null, null);
            }
          },
          {
            provide: AuthService,
            useFactory: () => {
              return new AuthService(null, null);
            }
          }
        ]
      }
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(SignupComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
