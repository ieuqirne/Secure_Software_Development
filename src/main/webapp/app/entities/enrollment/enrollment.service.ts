import { Injectable } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';

import { SERVER_API_URL } from 'app/app.constants';
import { createRequestOption } from 'app/shared';
import { IEnrollment } from 'app/shared/model/enrollment.model';

type EntityResponseType = HttpResponse<IEnrollment>;
type EntityArrayResponseType = HttpResponse<IEnrollment[]>;

@Injectable({ providedIn: 'root' })
export class EnrollmentService {
    private resourceUrl = SERVER_API_URL + 'api/enrollments';
    private resourceSearchUrl = SERVER_API_URL + 'api/_search/enrollments';

    constructor(private http: HttpClient) {}

    create(enrollment: IEnrollment): Observable<EntityResponseType> {
        return this.http.post<IEnrollment>(this.resourceUrl, enrollment, { observe: 'response' });
    }

    update(enrollment: IEnrollment): Observable<EntityResponseType> {
        return this.http.put<IEnrollment>(this.resourceUrl, enrollment, { observe: 'response' });
    }

    find(id: number): Observable<EntityResponseType> {
        return this.http.get<IEnrollment>(`${this.resourceUrl}/${id}`, { observe: 'response' });
    }

    query(req?: any): Observable<EntityArrayResponseType> {
        const options = createRequestOption(req);
        return this.http.get<IEnrollment[]>(this.resourceUrl, { params: options, observe: 'response' });
    }

    delete(id: number): Observable<HttpResponse<any>> {
        return this.http.delete<any>(`${this.resourceUrl}/${id}`, { observe: 'response' });
    }

    search(req?: any): Observable<EntityArrayResponseType> {
        const options = createRequestOption(req);
        return this.http.get<IEnrollment[]>(this.resourceSearchUrl, { params: options, observe: 'response' });
    }
}
