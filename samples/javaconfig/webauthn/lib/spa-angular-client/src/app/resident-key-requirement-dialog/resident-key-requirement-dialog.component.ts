import { Component, OnInit } from '@angular/core';
import {NgbActiveModal} from "@ng-bootstrap/ng-bootstrap";

@Component({
  selector: 'app-resident-key-requirement-dialog',
  templateUrl: './resident-key-requirement-dialog.component.html',
  styleUrls: ['./resident-key-requirement-dialog.component.css']
})
export class ResidentKeyRequirementDialogComponent implements OnInit {

  constructor(public activeModal: NgbActiveModal) { }

  ngOnInit() {
  }

}
