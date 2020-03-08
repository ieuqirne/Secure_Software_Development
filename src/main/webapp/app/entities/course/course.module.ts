import { NgModule, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterModule } from '@angular/router';

import { NapierUniPortalSharedModule } from 'app/shared';
import {
    CourseComponent,
    CourseDetailComponent,
    CourseUpdateComponent,
    CourseDeletePopupComponent,
    CourseDeleteDialogComponent,
    courseRoute,
    coursePopupRoute
} from './';

import { PipeModule } from '../../shared/pipes/pipe.module';

const ENTITY_STATES = [...courseRoute, ...coursePopupRoute];

@NgModule({
    imports: [NapierUniPortalSharedModule, RouterModule.forChild(ENTITY_STATES), PipeModule.forRoot()],
    declarations: [CourseComponent, CourseDetailComponent, CourseUpdateComponent, CourseDeleteDialogComponent, CourseDeletePopupComponent],
    entryComponents: [CourseComponent, CourseUpdateComponent, CourseDeleteDialogComponent, CourseDeletePopupComponent],
    schemas: [CUSTOM_ELEMENTS_SCHEMA]
})
export class NapierUniPortalCourseModule {}
