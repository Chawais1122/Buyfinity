import * as csrf from 'csrf';
import { Request, Response, NextFunction } from 'express';

const tokens = new csrf();

export function csrfMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session.csrfSecret) {
      req.session.csrfSecret = tokens.secretSync();
    }

    const csrfToken = req.headers['x-csrf-token'] as string;

    // Bypass CSRF validation for any authentication-related endpoints
    if (req.path.startsWith('/api/auth/')) {
      return next();
    }

    if (!csrfToken || !tokens.verify(req.session.csrfSecret, csrfToken)) {
      return res.status(403).json({ message: 'Invalid CSRF token' });
    }

    next();
  };
}
