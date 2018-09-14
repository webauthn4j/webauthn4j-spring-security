import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { DashboardComponent } from './dashboard.component';
import {of} from "rxjs/internal/observable/of";
import {ProfileService} from "../profile/profile.service";
import {RouterTestingModule} from "@angular/router/testing";

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ DashboardComponent ],
      imports: [
        RouterTestingModule
      ]
    }).overrideComponent(DashboardComponent, {
      set:{
        providers: [
          {
            provide: ProfileService,
            useFactory: ()=>{
              let profileServiceMock = new ProfileService(null, null);
              spyOn(profileServiceMock, "load").and.returnValue(of(null)); //TODO: return appropriate value
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
