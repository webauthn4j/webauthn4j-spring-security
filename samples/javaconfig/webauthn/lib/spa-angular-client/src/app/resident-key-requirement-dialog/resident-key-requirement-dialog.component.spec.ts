import {async, ComponentFixture, TestBed} from '@angular/core/testing';

import {ResidentKeyRequirementDialogComponent} from './resident-key-requirement-dialog.component';
import {NgbActiveModal, NgbModalModule} from "@ng-bootstrap/ng-bootstrap";
import {FormsModule} from "@angular/forms";

describe('ResidentKeyRequirementDialogComponent', () => {
  let component: ResidentKeyRequirementDialogComponent;
  let fixture: ComponentFixture<ResidentKeyRequirementDialogComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ResidentKeyRequirementDialogComponent ],
      imports: [
        NgbModalModule,
        FormsModule
      ]
    })
    .overrideComponent(ResidentKeyRequirementDialogComponent, {
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
