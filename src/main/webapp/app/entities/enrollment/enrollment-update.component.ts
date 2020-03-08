import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpResponse, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { JhiAlertService, JhiDataUtils } from 'ng-jhipster';

import { IEnrollment } from 'app/shared/model/enrollment.model';
import { EnrollmentService } from './enrollment.service';
import { IUser, UserService } from 'app/core';
import { ICourse } from 'app/shared/model/course.model';
import { CourseService } from 'app/entities/course';

@Component({
    selector: 'jhi-enrollment-update',
    templateUrl: './enrollment-update.component.html'
})
export class EnrollmentUpdateComponent implements OnInit {
    private _enrollment: IEnrollment;
    isSaving: boolean;

    users: IUser[];

    courses: ICourse[];

    constructor(
        private dataUtils: JhiDataUtils,
        private jhiAlertService: JhiAlertService,
        private enrollmentService: EnrollmentService,
        private userService: UserService,
        private courseService: CourseService,
        private activatedRoute: ActivatedRoute
    ) {}

    ngOnInit() {
        this.isSaving = false;
        this.activatedRoute.data.subscribe(({ enrollment }) => {
            this.enrollment = enrollment;
        });
        this.userService.query().subscribe(
            (res: HttpResponse<IUser[]>) => {
                this.users = res.body;
            },
            (res: HttpErrorResponse) => this.onError(res.message)
        );
        this.courseService.query().subscribe(
            (res: HttpResponse<ICourse[]>) => {
                this.courses = res.body;
            },
            (res: HttpErrorResponse) => this.onError(res.message)
        );
    }

    byteSize(field) {
        return this.dataUtils.byteSize(field);
    }

    openFile(contentType, field) {
        return this.dataUtils.openFile(contentType, field);
    }

    setFileData(event, entity, field, isImage) {
        this.dataUtils.setFileData(event, entity, field, isImage);
    }

    previousState() {
        window.history.back();
    }

    save() {
        this.isSaving = true;
        if (this.enrollment.id !== undefined) {
            this.subscribeToSaveResponse(this.enrollmentService.update(this.enrollment));
        } else {
            this.subscribeToSaveResponse(this.enrollmentService.create(this.enrollment));
        }
    }

    private subscribeToSaveResponse(result: Observable<HttpResponse<IEnrollment>>) {
        result.subscribe((res: HttpResponse<IEnrollment>) => this.onSaveSuccess(), (res: HttpErrorResponse) => this.onSaveError());
    }

    private onSaveSuccess() {
        this.isSaving = false;
        this.previousState();
    }

    private onSaveError() {
        this.isSaving = false;
    }

    private onError(errorMessage: string) {
        this.jhiAlertService.error(errorMessage, null, null);
    }

    trackUserById(index: number, item: IUser) {
        return item.id;
    }

    trackCourseById(index: number, item: ICourse) {
        return item.id;
    }

    getSelected(selectedVals: Array<any>, option: any) {
        if (selectedVals) {
            for (let i = 0; i < selectedVals.length; i++) {
                if (option.id === selectedVals[i].id) {
                    return selectedVals[i];
                }
            }
        }
        return option;
    }
    get enrollment() {
        return this._enrollment;
    }

    set enrollment(enrollment: IEnrollment) {
        this._enrollment = enrollment;
    }
}
