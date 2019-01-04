import {BrowserModule} from '@angular/platform-browser';
import {NgModule} from '@angular/core';

import {AppComponent} from './app.component';
import {LoginComponent} from './login/login.component';
import {AppRoutingModule} from "./app-routing.module";
import {RouterModule} from "@angular/router";
import {BrowserAnimationsModule} from "@angular/platform-browser/animations";
import {NgbModule} from "@ng-bootstrap/ng-bootstrap"
import {FormsModule} from "@angular/forms";
import {HTTP_INTERCEPTORS, HttpClientModule} from "@angular/common/http";
import {AuthenticatorLoginComponent} from './authenticator-login/authenticator-login.component';
import {PasswordLoginComponent} from './password-login/password-login.component';
import {DashboardComponent} from "./dashboard/dashboard.component";
import {SignupComponent} from "./signup/signup.component";
import {AuthenticatorDialogComponent} from "./authenticator-dialog/authenticator-dialog.component";
import {AuthenticatorRegistrationReconfirmationDialogComponent} from "./authenticator-registration-reconfirmation-dialog/authenticator-registration-reconfirmation-dialog.component";
import {ProfileComponent} from "./profile/profile.component";
import {PageNotFoundComponent} from "./page-not-found/page-not-found.component";
import {HeaderComponent} from "./header/header.component";
import {AuthGuard} from "./auth/auth.guard";
import {AuthInterceptor} from "./auth/auth.interceptor";
import {ResidentKeyRequirementDialogComponent} from './resident-key-requirement-dialog/resident-key-requirement-dialog.component';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    AuthenticatorLoginComponent,
    PasswordLoginComponent,
    DashboardComponent,
    SignupComponent,
    AuthenticatorDialogComponent,
    AuthenticatorRegistrationReconfirmationDialogComponent,
    ProfileComponent,
    PageNotFoundComponent,
    HeaderComponent,
    ResidentKeyRequirementDialogComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    AppRoutingModule,
    HttpClientModule,
    FormsModule,
    NgbModule
  ],
  exports: [
    RouterModule
  ],
  providers: [
    AuthGuard,
    {provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true},
  ],
  bootstrap: [AppComponent],
  entryComponents: [
    AuthenticatorDialogComponent,
    AuthenticatorRegistrationReconfirmationDialogComponent,
    ResidentKeyRequirementDialogComponent
  ]

})
export class AppModule {
}
