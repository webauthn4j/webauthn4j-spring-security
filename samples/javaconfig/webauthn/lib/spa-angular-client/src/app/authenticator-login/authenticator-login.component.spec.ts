import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthenticatorLoginComponent } from './authenticator-login.component';
import {NgbAlertModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";
import {AuthService} from "../auth/auth.service";
import {of} from "rxjs/internal/observable/of";
import {RouterTestingModule} from "@angular/router/testing";
import {ProfileComponent} from "../profile/profile.component";

describe('AuthenticatorLoginComponent', () => {
  let component: AuthenticatorLoginComponent;
  let fixture: ComponentFixture<AuthenticatorLoginComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [
        AuthenticatorLoginComponent,
        ProfileComponent
      ],
      imports: [
        NgbAlertModule,
        FormsModule,
        RouterTestingModule.withRoutes([
          { path: 'profile', component: ProfileComponent },
        ])
      ]
    }).overrideComponent(AuthenticatorLoginComponent, {
      set:{
        providers: [
          {
            provide: AuthService,
            useFactory: ()=>{
              let authServiceMock = new AuthService(null, null);
              spyOn(authServiceMock, "loginWithPublicKeyCredential").and.returnValue(of(""));
              spyOn(authServiceMock, "getAuthenticationStatus").and.returnValue(of("Anonymous"));
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
