import { environment } from "./environments/environment";
import { enableProdMode } from "@angular/core";
import { AppModule } from "./app/app.module";
import { platformBrowser } from "@angular/platform-browser";
import { platformBrowserDynamic } from "@angular/platform-browser-dynamic";

if (environment.production) {
  enableProdMode();
}

if (environment.production) {
  platformBrowser()
    .bootstrapModule(AppModule)
    .catch((err) => console.error(err));
} else {
  platformBrowserDynamic()
    .bootstrapModule(AppModule)
    .catch((err) => console.error(err));
}
