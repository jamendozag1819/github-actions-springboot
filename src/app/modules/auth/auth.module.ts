import { CommonModule } from "@angular/common";
import { NgModule, provideZoneChangeDetection } from "@angular/core";
import { AngularMaterialUIModule } from "../../shared/angular-material-ui/angular-material-ui.module";
import { AngularSettingsModule } from "../../shared/angular-settings/angular-settings.module";
import { EffectsModule } from "@ngrx/effects";
import { StoreModule } from "@ngrx/store";
import { AuthEffects } from "./store/auth.effects";
import * as authReducer from "./store/auth.reducer";
import { provideRouter, RouterModule } from "@angular/router";
import { routes } from "./auth.route";
import { LoginComponent } from "./login/login.component";
import { RegisterComponent } from "./register/register.component";
import { ForgotComponent } from "./forgot/forgot.component";

@NgModule({
  declarations: [LoginComponent, RegisterComponent, ForgotComponent],
  imports: [
    CommonModule,
    AngularMaterialUIModule,
    AngularSettingsModule,
    RouterModule.forRoot(routes, { useHash: true }),
    StoreModule.forFeature(authReducer.AuthFeatureReducer),
    EffectsModule.forFeature([AuthEffects])
  ],
  providers: [provideZoneChangeDetection({ eventCoalescing: true }), provideRouter(routes)]
})
export class AuthModule {}
