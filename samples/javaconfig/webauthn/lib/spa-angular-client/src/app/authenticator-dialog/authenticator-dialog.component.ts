import { Component, OnInit } from '@angular/core';
import { NgbActiveModal, NgbModal } from '@ng-bootstrap/ng-bootstrap';

@Component({
  selector: 'app-authenticator-dialog',
  templateUrl: './authenticator-dialog.component.html',
  styleUrls: ['./authenticator-dialog.component.css']
})
export class AuthenticatorDialogComponent implements OnInit {

  authenticator: {name: String} = {name: ""};

  constructor(public activeModal: NgbActiveModal) { }

  ngOnInit() {
  }

  save(){
    this.activeModal.close(this.authenticator);
  }

}
