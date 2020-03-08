/* tslint:disable max-line-length */
import { ComponentFixture, TestBed, inject, fakeAsync, tick } from '@angular/core/testing';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Observable, of } from 'rxjs';
import { JhiEventManager } from 'ng-jhipster';

import { NapierUniPortalTestModule } from '../../../test.module';
import { EnrollmentDeleteDialogComponent } from 'app/entities/enrollment/enrollment-delete-dialog.component';
import { EnrollmentService } from 'app/entities/enrollment/enrollment.service';

describe('Component Tests', () => {
    describe('Enrollment Management Delete Component', () => {
        let comp: EnrollmentDeleteDialogComponent;
        let fixture: ComponentFixture<EnrollmentDeleteDialogComponent>;
        let service: EnrollmentService;
        let mockEventManager: any;
        let mockActiveModal: any;

        beforeEach(() => {
            TestBed.configureTestingModule({
                imports: [NapierUniPortalTestModule],
                declarations: [EnrollmentDeleteDialogComponent]
            })
                .overrideTemplate(EnrollmentDeleteDialogComponent, '')
                .compileComponents();
            fixture = TestBed.createComponent(EnrollmentDeleteDialogComponent);
            comp = fixture.componentInstance;
            service = fixture.debugElement.injector.get(EnrollmentService);
            mockEventManager = fixture.debugElement.injector.get(JhiEventManager);
            mockActiveModal = fixture.debugElement.injector.get(NgbActiveModal);
        });

        describe('confirmDelete', () => {
            it('Should call delete service on confirmDelete', inject(
                [],
                fakeAsync(() => {
                    // GIVEN
                    spyOn(service, 'delete').and.returnValue(of({}));

                    // WHEN
                    comp.confirmDelete(123);
                    tick();

                    // THEN
                    expect(service.delete).toHaveBeenCalledWith(123);
                    expect(mockActiveModal.dismissSpy).toHaveBeenCalled();
                    expect(mockEventManager.broadcastSpy).toHaveBeenCalled();
                })
            ));
        });
    });
});
