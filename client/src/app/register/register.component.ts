import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';
import { AccountService } from '../_services/account.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  @Output() cancelledRegister = new EventEmitter();
  model: any = {};
  constructor(private accountservice: AccountService) { }

  ngOnInit(): void {
  }
  register() {
    this.accountservice.register(this.model).subscribe(response => {
      console.log(response);
      this.cancel();
    }, error => {
      console.log(error);
    })
  }
  cancel() {
    this.cancelledRegister.emit(false);
  }
}
