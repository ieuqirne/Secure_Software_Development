import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';

import { NapierUniPortalEnrollmentModule } from './enrollment/enrollment.module';
import { NapierUniPortalCourseModule } from './course/course.module';
import { NapierUniPortalProgramModule } from './program/program.module';
/* jhipster-needle-add-entity-module-import - JHipster will add entity modules imports here */

@NgModule({
    // prettier-ignore
    imports: [
        NapierUniPortalEnrollmentModule,
        NapierUniPortalCourseModule,
        NapierUniPortalProgramModule,
        /* jhipster-needle-add-entity-module - JHipster will add entity modules here */
    ],
    declarations: [],
    entryComponents: [],
    providers: [],
    schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class NapierUniPortalEntityModule {}
