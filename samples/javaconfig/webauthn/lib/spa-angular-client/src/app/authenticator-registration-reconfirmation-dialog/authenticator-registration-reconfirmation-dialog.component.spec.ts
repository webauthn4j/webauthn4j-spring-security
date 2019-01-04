import {async, ComponentFixture, TestBed} from '@angular/core/testing';

import {AuthenticatorRegistrationReconfirmationDialogComponent} from './authenticator-registration-reconfirmation-dialog.component';
import {FormsModule} from "@angular/forms";
import {NgbActiveModal, NgbModalModule} from "@ng-bootstrap/ng-bootstrap";

describe('AuthenticatorRegistrationReconfirmationDialogComponent', () => {
  let component: AuthenticatorRegistrationReconfirmationDialogComponent;
  let fixture: ComponentFixture<AuthenticatorRegistrationReconfirmationDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ AuthenticatorRegistrationReconfirmationDialogComponent ],
      imports: [
        NgbModalModule,
        FormsModule
      ]
    }).overrideComponent(AuthenticatorRegistrationReconfirmationDialogComponent, {
      set:{
        providers: [
          {
            provide: NgbActiveModal,
            useFactory: ()=>{
              return new NgbActiveModal();
            }
          }
        ]
      }
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(AuthenticatorRegistrationReconfirmationDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
