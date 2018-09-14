import { Component, OnInit } from '@angular/core';
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";

@Component({
  selector: 'app-authenticator-registration-reconfirmation-dialog',
  templateUrl: './authenticator-registration-reconfirmation-dialog.component.html',
  styleUrls: ['./authenticator-registration-reconfirmation-dialog.component.css']
})
export class AuthenticatorRegistrationReconfirmationDialogComponent implements OnInit {

  constructor(public activeModal: NgbActiveModal) { }

  ngOnInit() {
  }

}
