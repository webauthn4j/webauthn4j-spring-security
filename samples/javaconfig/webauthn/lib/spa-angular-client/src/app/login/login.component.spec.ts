import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { LoginComponent } from './login.component';
import {AuthenticatorLoginComponent} from "../authenticator-login/authenticator-login.component";
import {AuthService} from "../auth/auth.service";
import {PasswordLoginComponent} from "../password-login/password-login.component";
import {FormsModule} from "@angular/forms";
import {NgbAlertModule} from "@ng-bootstrap/ng-bootstrap";

import {RouterTestingModule} from "@angular/router/testing";
import {of} from "rxjs/internal/observable/of";

describe('LoginComponent', () => {
  let component: LoginComponent;
  let fixture: ComponentFixture<LoginComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ LoginComponent, PasswordLoginComponent, AuthenticatorLoginComponent],
      imports: [
        FormsModule,
        NgbAlertModule,
        RouterTestingModule
      ]
    }).overrideComponent(LoginComponent, {
      set:{
        providers: [
          {
            provide: AuthService,
            useFactory: ()=>{
              let authServiceMock = new AuthService(null, null);
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
    fixture = TestBed.createComponent(LoginComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
