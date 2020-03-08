import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { JhiDataUtils } from 'ng-jhipster';

import { IEnrollment } from 'app/shared/model/enrollment.model';

@Component({
    selector: 'jhi-enrollment-detail',
    templateUrl: './enrollment-detail.component.html'
})
export class EnrollmentDetailComponent implements OnInit {
    enrollment: IEnrollment;

    constructor(private dataUtils: JhiDataUtils, private activatedRoute: ActivatedRoute) {}

    ngOnInit() {
        this.activatedRoute.data.subscribe(({ enrollment }) => {
            this.enrollment = enrollment;
        });
    }

    byteSize(field) {
        return this.dataUtils.byteSize(field);
    }

    openFile(contentType, field) {
        return this.dataUtils.openFile(contentType, field);
    }
    previousState() {
        window.history.back();
    }
}
