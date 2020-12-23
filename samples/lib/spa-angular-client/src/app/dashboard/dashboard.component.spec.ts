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

import {DashboardComponent} from './dashboard.component';
import {of} from "rxjs/internal/observable/of";
import {ProfileService} from "../profile/profile.service";
import {RouterTestingModule} from "@angular/router/testing";

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [DashboardComponent],
      imports: [
        RouterTestingModule
      ]
    }).overrideComponent(DashboardComponent, {
      set: {
        providers: [
          {
            provide: ProfileService,
            useFactory: () => {
              let profileServiceMock = new ProfileService(null, null);
              spyOn(profileServiceMock, "load").and.returnValue(of({
                userHandle: "userHandle",
                firstName: "firstName",
                lastName: "lastName",
                emailAddress: "dummy@example.com",
                password: "password",
                authenticators: [],
                singleFactorAuthenticationAllowed: true
              }));
              return profileServiceMock;
            }
          }

        ]
      }
    })
      .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
