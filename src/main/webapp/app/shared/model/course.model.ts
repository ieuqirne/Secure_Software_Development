import { IProgram } from 'app/shared/model//program.model';
import { IEnrollment } from 'app/shared/model//enrollment.model';

export interface ICourse {
    id?: number;
    title?: string;
    description?: any;
    programs?: IProgram[];
    enrollments?: IEnrollment[];
}

export class Course implements ICourse {
    constructor(
        public id?: number,
        public title?: string,
        public description?: any,
        public programs?: IProgram[],
        public enrollments?: IEnrollment[]
    ) {}
}
