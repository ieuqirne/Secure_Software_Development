import { Injectable } from '@angular/core';
import { HttpResponse } from '@angular/common/http';
import { Resolve, ActivatedRouteSnapshot, RouterStateSnapshot, Routes } from '@angular/router';
import { UserRouteAccessService } from 'app/core';
import { of } from 'rxjs';
import { map } from 'rxjs/operators';
import { Enrollment } from 'app/shared/model/enrollment.model';
import { EnrollmentService } from './enrollment.service';
import { EnrollmentComponent } from './enrollment.component';
import { EnrollmentDetailComponent } from './enrollment-detail.component';
import { EnrollmentUpdateComponent } from './enrollment-update.component';
import { EnrollmentDeletePopupComponent } from './enrollment-delete-dialog.component';
import { IEnrollment } from 'app/shared/model/enrollment.model';

@Injectable({ providedIn: 'root' })
export class EnrollmentResolve implements Resolve<IEnrollment> {
    constructor(private service: EnrollmentService) {}

    resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot) {
        const id = route.params['id'] ? route.params['id'] : null;
        if (id) {
            return this.service.find(id).pipe(map((enrollment: HttpResponse<Enrollment>) => enrollment.body));
        }
        return of(new Enrollment());
    }
}

export const enrollmentRoute: Routes = [
    {
        path: 'enrollment',
        component: EnrollmentComponent,
        data: {
            authorities: ['ROLE_USER'],
            pageTitle: 'Enrollments'
        },
        canActivate: [UserRouteAccessService]
    },
    {
        path: 'enrollment/:id/view',
        component: EnrollmentDetailComponent,
        resolve: {
            enrollment: EnrollmentResolve
        },
        data: {
            authorities: ['ROLE_USER'],
            pageTitle: 'Enrollments'
        },
        canActivate: [UserRouteAccessService]
    },
    {
        path: 'enrollment/new',
        component: EnrollmentUpdateComponent,
        resolve: {
            enrollment: EnrollmentResolve
        },
        data: {
            authorities: ['ROLE_USER'],
            pageTitle: 'Enrollments'
        },
        canActivate: [UserRouteAccessService]
    },
    {
        path: 'enrollment/:id/edit',
        component: EnrollmentUpdateComponent,
        resolve: {
            enrollment: EnrollmentResolve
        },
        data: {
            authorities: ['ROLE_USER'],
            pageTitle: 'Enrollments'
        },
        canActivate: [UserRouteAccessService]
    }
];

export const enrollmentPopupRoute: Routes = [
    {
        path: 'enrollment/:id/delete',
        component: EnrollmentDeletePopupComponent,
        resolve: {
            enrollment: EnrollmentResolve
        },
        data: {
            authorities: ['ROLE_USER'],
            pageTitle: 'Enrollments'
        },
        canActivate: [UserRouteAccessService],
        outlet: 'popup'
    }
];
