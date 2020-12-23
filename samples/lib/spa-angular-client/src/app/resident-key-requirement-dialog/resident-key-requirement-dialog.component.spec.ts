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

import {ResidentKeyRequirementDialogComponent} from './resident-key-requirement-dialog.component';
import {NgbActiveModal, NgbModalModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";

describe('ResidentKeyRequirementDialogComponent', () => {
  let component: ResidentKeyRequirementDialogComponent;
  let fixture: ComponentFixture<ResidentKeyRequirementDialogComponent>;

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      declarations: [ResidentKeyRequirementDialogComponent],
      imports: [
        NgbModalModule,
        FormsModule
      ]
    })
      .overrideComponent(ResidentKeyRequirementDialogComponent, {
        set: {
          providers: [
            {
              provide: NgbActiveModal,
              useFactory: () => {
                return new NgbActiveModal();
              }
            }
          ]
        }
      }).compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ResidentKeyRequirementDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
