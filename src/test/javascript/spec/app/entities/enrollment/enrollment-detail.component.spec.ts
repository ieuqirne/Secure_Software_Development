/* tslint:disable max-line-length */
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute } from '@angular/router';
import { of } from 'rxjs';

import { NapierUniPortalTestModule } from '../../../test.module';
import { EnrollmentDetailComponent } from 'app/entities/enrollment/enrollment-detail.component';
import { Enrollment } from 'app/shared/model/enrollment.model';

describe('Component Tests', () => {
    describe('Enrollment Management Detail Component', () => {
        let comp: EnrollmentDetailComponent;
        let fixture: ComponentFixture<EnrollmentDetailComponent>;
        const route = ({ data: of({ enrollment: new Enrollment(123) }) } as any) as ActivatedRoute;

        beforeEach(() => {
            TestBed.configureTestingModule({
                imports: [NapierUniPortalTestModule],
                declarations: [EnrollmentDetailComponent],
                providers: [{ provide: ActivatedRoute, useValue: route }]
            })
                .overrideTemplate(EnrollmentDetailComponent, '')
                .compileComponents();
            fixture = TestBed.createComponent(EnrollmentDetailComponent);
            comp = fixture.componentInstance;
        });

        describe('OnInit', () => {
            it('Should call load all on init', () => {
                // GIVEN

                // WHEN
                comp.ngOnInit();

                // THEN
                expect(comp.enrollment).toEqual(jasmine.objectContaining({ id: 123 }));
            });
        });
    });
});
