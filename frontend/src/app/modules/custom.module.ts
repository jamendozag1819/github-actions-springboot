import { NgModule } from "@angular/core";
import { AuthModule } from "./auth/auth.module";

@NgModule({
  exports: [AuthModule]
})
export class CustomModule {}
