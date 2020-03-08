import { NgModule } from '@angular/core';

import { NapierUniPortalSharedLibsModule, JhiAlertComponent, JhiAlertErrorComponent } from './';

@NgModule({
    imports: [NapierUniPortalSharedLibsModule],
    declarations: [JhiAlertComponent, JhiAlertErrorComponent],
    exports: [NapierUniPortalSharedLibsModule, JhiAlertComponent, JhiAlertErrorComponent]
})
export class NapierUniPortalSharedCommonModule {}
