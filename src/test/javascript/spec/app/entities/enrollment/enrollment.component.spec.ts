/* tslint:disable max-line-length */
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of } from 'rxjs';
import { HttpHeaders, HttpResponse } from '@angular/common/http';

import { NapierUniPortalTestModule } from '../../../test.module';
import { EnrollmentComponent } from 'app/entities/enrollment/enrollment.component';
import { EnrollmentService } from 'app/entities/enrollment/enrollment.service';
import { Enrollment } from 'app/shared/model/enrollment.model';

describe('Component Tests', () => {
    describe('Enrollment Management Component', () => {
        let comp: EnrollmentComponent;
        let fixture: ComponentFixture<EnrollmentComponent>;
        let service: EnrollmentService;

        beforeEach(() => {
            TestBed.configureTestingModule({
                imports: [NapierUniPortalTestModule],
                declarations: [EnrollmentComponent],
                providers: []
            })
                .overrideTemplate(EnrollmentComponent, '')
                .compileComponents();

            fixture = TestBed.createComponent(EnrollmentComponent);
            comp = fixture.componentInstance;
            service = fixture.debugElement.injector.get(EnrollmentService);
        });

        it('Should call load all on init', () => {
            // GIVEN
            const headers = new HttpHeaders().append('link', 'link;link');
            spyOn(service, 'query').and.returnValue(
                of(
                    new HttpResponse({
                        body: [new Enrollment(123)],
                        headers
                    })
                )
            );

            // WHEN
            comp.ngOnInit();

            // THEN
            expect(service.query).toHaveBeenCalled();
            expect(comp.enrollments[0]).toEqual(jasmine.objectContaining({ id: 123 }));
        });
    });
});
