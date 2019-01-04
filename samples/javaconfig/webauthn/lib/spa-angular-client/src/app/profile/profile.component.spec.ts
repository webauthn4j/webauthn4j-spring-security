import {async, ComponentFixture, TestBed} from '@angular/core/testing';

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

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ProfileComponent ],
      imports: [
        FormsModule,
        NgbAlertModule,
        RouterTestingModule
      ]
    }).overrideComponent(ProfileComponent, {
      set:{
        providers: [
          {
            provide: AuthService,
            useFactory: ()=>{
              let authServiceMock = new AuthService(null, null);
              spyOn(authServiceMock, "getAuthenticationStatus").and.returnValue(of("Anonymous"));
              return authServiceMock;
            }
          },
          {
            provide: ProfileService,
            useFactory: ()=>{
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
