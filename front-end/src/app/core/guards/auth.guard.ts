import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { catchError, map, of } from 'rxjs';
import { AuthService } from '../services/auth.service';

/**
 * Protege as telas logadas. O cache local só pinta a UI; quem decide se a
 * sessão vale é o backend (cookie httpOnly), por isso a checagem via /me,
 * que também atualiza papel e plano no cache.
 */
export const authGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (!auth.getCachedUser()) {
    return router.parseUrl('/login');
  }

  return auth.me().pipe(
    map((session) => {
      auth.updateCachedUser({
        role: session.role,
        email: session.email,
        ...(session.name ? { name: session.name } : {}),
        ...(session.plan ? { plan: session.plan } : {}),
      });
      return true;
    }),
    catchError(() => of(router.parseUrl('/login')))
  );
};
