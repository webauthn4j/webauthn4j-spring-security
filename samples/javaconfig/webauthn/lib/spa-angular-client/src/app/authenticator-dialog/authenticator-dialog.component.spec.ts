import {async, ComponentFixture, TestBed} from '@angular/core/testing';

import {AuthenticatorDialogComponent} from './authenticator-dialog.component';
import {NgbActiveModal, NgbModalModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";

describe('AuthenticatorDialogComponent', () => {
  let component: AuthenticatorDialogComponent;
  let fixture: ComponentFixture<AuthenticatorDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ AuthenticatorDialogComponent ],
      imports: [
        NgbModalModule,
        FormsModule
      ]
    }).overrideComponent(AuthenticatorDialogComponent, {
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
    fixture = TestBed.createComponent(AuthenticatorDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
