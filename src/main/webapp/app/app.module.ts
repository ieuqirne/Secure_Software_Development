import './vendor.ts';

import { NgModule, Injector } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { Ng2Webstorage } from 'ngx-webstorage';
import { JhiEventManager } from 'ng-jhipster';

import { AuthExpiredInterceptor } from './blocks/interceptor/auth-expired.interceptor';
import { ErrorHandlerInterceptor } from './blocks/interceptor/errorhandler.interceptor';
import { NotificationInterceptor } from './blocks/interceptor/notification.interceptor';
import { NapierUniPortalSharedModule } from 'app/shared';
import { NapierUniPortalCoreModule } from 'app/core';
import { NapierUniPortalAppRoutingModule } from './app-routing.module';
import { NapierUniPortalHomeModule } from './home/home.module';
import { NapierUniPortalAccountModule } from './account/account.module';
import { NapierUniPortalEntityModule } from './entities/entity.module';
import { StateStorageService } from 'app/core/auth/state-storage.service';
// jhipster-needle-angular-add-module-import JHipster will add new module here
import { JhiMainComponent, NavbarComponent, FooterComponent, PageRibbonComponent, ErrorComponent } from './layouts';

@NgModule({
    imports: [
        BrowserModule,
        NapierUniPortalAppRoutingModule,
        Ng2Webstorage.forRoot({ prefix: 'jhi', separator: '-' }),
        NapierUniPortalSharedModule,
        NapierUniPortalCoreModule,
        NapierUniPortalHomeModule,
        NapierUniPortalAccountModule,
        NapierUniPortalEntityModule
        // jhipster-needle-angular-add-module JHipster will add new module here
    ],
    declarations: [JhiMainComponent, NavbarComponent, ErrorComponent, PageRibbonComponent, FooterComponent],
    providers: [
        {
            provide: HTTP_INTERCEPTORS,
            useClass: AuthExpiredInterceptor,
            multi: true,
            deps: [StateStorageService, Injector]
        },
        {
            provide: HTTP_INTERCEPTORS,
            useClass: ErrorHandlerInterceptor,
            multi: true,
            deps: [JhiEventManager]
        },
        {
            provide: HTTP_INTERCEPTORS,
            useClass: NotificationInterceptor,
            multi: true,
            deps: [Injector]
        }
    ],
    bootstrap: [JhiMainComponent]
})
export class NapierUniPortalAppModule {}
