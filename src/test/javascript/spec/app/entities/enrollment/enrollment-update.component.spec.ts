/* tslint:disable max-line-length */
import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { HttpResponse } from '@angular/common/http';
import { Observable, of } from 'rxjs';

import { NapierUniPortalTestModule } from '../../../test.module';
import { EnrollmentUpdateComponent } from 'app/entities/enrollment/enrollment-update.component';
import { EnrollmentService } from 'app/entities/enrollment/enrollment.service';
import { Enrollment } from 'app/shared/model/enrollment.model';

describe('Component Tests', () => {
    describe('Enrollment Management Update Component', () => {
        let comp: EnrollmentUpdateComponent;
        let fixture: ComponentFixture<EnrollmentUpdateComponent>;
        let service: EnrollmentService;

        beforeEach(() => {
            TestBed.configureTestingModule({
                imports: [NapierUniPortalTestModule],
                declarations: [EnrollmentUpdateComponent]
            })
                .overrideTemplate(EnrollmentUpdateComponent, '')
                .compileComponents();

            fixture = TestBed.createComponent(EnrollmentUpdateComponent);
            comp = fixture.componentInstance;
            service = fixture.debugElement.injector.get(EnrollmentService);
        });

        describe('save', () => {
            it(
                'Should call update service on save for existing entity',
                fakeAsync(() => {
                    // GIVEN
                    const entity = new Enrollment(123);
                    spyOn(service, 'update').and.returnValue(of(new HttpResponse({ body: entity })));
                    comp.enrollment = entity;
                    // WHEN
                    comp.save();
                    tick(); // simulate async

                    // THEN
                    expect(service.update).toHaveBeenCalledWith(entity);
                    expect(comp.isSaving).toEqual(false);
                })
            );

            it(
                'Should call create service on save for new entity',
                fakeAsync(() => {
                    // GIVEN
                    const entity = new Enrollment();
                    spyOn(service, 'create').and.returnValue(of(new HttpResponse({ body: entity })));
                    comp.enrollment = entity;
                    // WHEN
                    comp.save();
                    tick(); // simulate async

                    // THEN
                    expect(service.create).toHaveBeenCalledWith(entity);
                    expect(comp.isSaving).toEqual(false);
                })
            );
        });
    });
});
