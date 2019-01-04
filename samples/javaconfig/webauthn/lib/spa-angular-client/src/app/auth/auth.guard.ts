import {Injectable} from '@angular/core';
import {ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot} from '@angular/router';
import {map} from "rxjs/operators";
import {AuthService} from "./auth.service";
import {Observable} from "rxjs/internal/Observable";

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {

  }

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<boolean> | Promise<boolean> | boolean {
    return this.authService.getAuthenticationStatus().pipe(map(status => {
        if(status == "Authenticated"){
          return true;
        }
        else {
          this.router.navigate(["/login"]);
          return false;
        }
    }));
  }
}
