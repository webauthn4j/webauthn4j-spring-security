import { TestBed, async } from '@angular/core/testing';
import { AppComponent } from './app.component';
import {RouterTestingModule} from "@angular/router/testing";
import {HeaderComponent} from "./header/header.component";
import {of} from "rxjs/internal/observable/of";
import {AuthService} from "./auth/auth.service";

describe('AppComponent', () => {
  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [
        AppComponent,
        HeaderComponent
      ],
      imports: [
        RouterTestingModule
      ]
    }).overrideComponent(AppComponent, {
      set:{
        providers: [
          {
            provide: AuthService,
            useFactory: ()=>{
              let authServiceMock = new AuthService(null, null);
              spyOn(authServiceMock, "loginWithPublicKeyCredential").and.returnValue(of(null));
              spyOn(authServiceMock, "getAuthenticationStatus").and.returnValue(of("Anonymous"));
              return authServiceMock;
            }
          }
        ]
      }
    }).compileComponents();
  }));
  it('should create the app', async(() => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.debugElement.componentInstance;
    expect(app).toBeTruthy();
  }));
  it(`should have as title 'sample-client'`, async(() => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.debugElement.componentInstance;
    expect(app.title).toEqual('sample-client');
  }));
  // it('should render title in a h1 tag', async(() => {
  //   const fixture = TestBed.createComponent(AppComponent);
  //   fixture.detectChanges();
  //   const compiled = fixture.debugElement.nativeElement;
  //   expect(compiled.querySelector('h1').textContent).toContain('Welcome to sample-client!');
  // }));
});
