import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterModule } from '@angular/router';

import { NapierUniPortalSharedModule } from 'app/shared';
import { NapierUniPortalAdminModule } from 'app/admin/admin.module';
import {
    EnrollmentComponent,
    EnrollmentDetailComponent,
    EnrollmentUpdateComponent,
    EnrollmentDeletePopupComponent,
    EnrollmentDeleteDialogComponent,
    enrollmentRoute,
    enrollmentPopupRoute
} from './';

const ENTITY_STATES = [...enrollmentRoute, ...enrollmentPopupRoute];

@NgModule({
    imports: [NapierUniPortalSharedModule, NapierUniPortalAdminModule, RouterModule.forChild(ENTITY_STATES)],
    declarations: [
        EnrollmentComponent,
        EnrollmentDetailComponent,
        EnrollmentUpdateComponent,
        EnrollmentDeleteDialogComponent,
        EnrollmentDeletePopupComponent
    ],
    entryComponents: [EnrollmentComponent, EnrollmentUpdateComponent, EnrollmentDeleteDialogComponent, EnrollmentDeletePopupComponent],
    schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class NapierUniPortalEnrollmentModule {}
