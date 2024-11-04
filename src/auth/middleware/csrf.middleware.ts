import * as csrf from 'csrf';
import { Request, Response, NextFunction } from 'express';

export function csrfMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    const tokens = new csrf();
    // Bypass CSRF validation for any authentication-related endpoints
    if (req.path.startsWith('/api/auth/')) {
      return next();
    }
    // For all other routes, enforce CSRF token validation
    const csrfToken = req.headers['x-csrf-token'] as string;

    if (!csrfToken || !tokens.verify(req.session.csrfSecret, csrfToken)) {
      return res.status(403).json({ message: 'Invalid CSRF token' });
    }

    next();
  };
}
