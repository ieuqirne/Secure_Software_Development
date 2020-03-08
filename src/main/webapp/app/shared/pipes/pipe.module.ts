import { NgModule } from '@angular/core';
import {CommonModule} from '@angular/common';

import {SafePipe} from './safe.pipe';

@NgModule({
  declarations: [SafePipe],
  imports: [],
  exports: [SafePipe]
})

export class PipeModule {
    static forRoot() {
      return {
          ngModule: PipeModule,
          providers: [],
      };
   }
}
