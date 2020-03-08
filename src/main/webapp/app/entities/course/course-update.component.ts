import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpResponse, HttpErrorResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { JhiAlertService, JhiDataUtils } from 'ng-jhipster';

import { ICourse } from 'app/shared/model/course.model';
import { CourseService } from './course.service';
import { IProgram } from 'app/shared/model/program.model';
import { ProgramService } from 'app/entities/program';
import { IEnrollment } from 'app/shared/model/enrollment.model';
import { EnrollmentService } from 'app/entities/enrollment';

@Component({
    selector: 'jhi-course-update',
    templateUrl: './course-update.component.html'
})
export class CourseUpdateComponent implements OnInit {
    private _course: ICourse;
    isSaving: boolean;

    programs: IProgram[];

    enrollments: IEnrollment[];

    constructor(
        private dataUtils: JhiDataUtils,
        private jhiAlertService: JhiAlertService,
        private courseService: CourseService,
        private programService: ProgramService,
        private enrollmentService: EnrollmentService,
        private activatedRoute: ActivatedRoute
    ) {}

    ngOnInit() {
        this.isSaving = false;
        this.activatedRoute.data.subscribe(({ course }) => {
            this.course = course;
        });
        this.programService.query().subscribe(
            (res: HttpResponse<IProgram[]>) => {
                this.programs = res.body;
            },
            (res: HttpErrorResponse) => this.onError(res.message)
        );
        this.enrollmentService.query().subscribe(
            (res: HttpResponse<IEnrollment[]>) => {
                this.enrollments = res.body;
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
        if (this.course.id !== undefined) {
            this.subscribeToSaveResponse(this.courseService.update(this.course));
        } else {
            this.subscribeToSaveResponse(this.courseService.create(this.course));
        }
    }

    private subscribeToSaveResponse(result: Observable<HttpResponse<ICourse>>) {
        result.subscribe((res: HttpResponse<ICourse>) => this.onSaveSuccess(), (res: HttpErrorResponse) => this.onSaveError());
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

    trackProgramById(index: number, item: IProgram) {
        return item.id;
    }

    trackEnrollmentById(index: number, item: IEnrollment) {
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
    get course() {
        return this._course;
    }

    set course(course: ICourse) {
        this._course = course;
    }
}
