// Visibility: findings outside the program scope are hidden until the "Show hidden" toggle is on.
import { isOutOfProgram } from '../core/program.js';
export const hiddenReason = (f, app) => (app.program && isOutOfProgram(f, app.store.pageHost, app.program.rules) ? 'out of program scope' : '');
export const isShown = (f, app) => !!app.showHidden || !hiddenReason(f, app);
