import { Moment } from 'moment';
import { ICourse } from 'app/shared/model//course.model';

export interface IProgram {
    id?: number;
    name?: string;
    startDate?: Moment;
    maxStudents?: number;
    courses?: ICourse[];
}

export class Program implements IProgram {
    constructor(
        public id?: number,
        public name?: string,
        public startDate?: Moment,
        public maxStudents?: number,
        public courses?: ICourse[]
    ) {}
}
