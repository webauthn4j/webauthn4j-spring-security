import { Component, OnInit } from '@angular/core';
import {ProfileService} from "../profile/profile.service";
import {DashboardViewModel} from "./dashboard.view-model";

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {

  constructor(private profileService: ProfileService) { }

  dashboard: DashboardViewModel = {
    firstName: "",
    lastName: ""
  };

  ngOnInit() {
    this.profileService.load().subscribe((user)=>{
      this.dashboard.firstName = user.firstName;
      this.dashboard.lastName = user.lastName;
    });
  }

}
