import helmet from 'helmet';
import { doubleCsrf } from 'csrf-csrf';
import { AppModule } from './app.module';
import { NestFactory } from '@nestjs/core';
import rateLimit from 'express-rate-limit';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Validation Pipe Configuration
  const apiValidationPipes: ValidationPipe = new ValidationPipe({
    transform: true,
    forbidNonWhitelisted: true,
    errorHttpStatusCode: 400,
    transformOptions: { enableImplicitConversion: true },
  });

  // Enable CORS
  app.enableCors({ origin: '*', credentials: true });

  // Set Global Prefix for API
  app.setGlobalPrefix('api');

  // Use Global Validation Pipes
  app.useGlobalPipes(apiValidationPipes);

  // Middleware for cookie parsing
  app.use(cookieParser());

  // Rate Limiting Middleware
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: {
      statusCode: 429,
      message: 'Too many requests, please try again later.',
    },
  });

  app.use(limiter);

  // CSRF Protection
  const { doubleCsrfProtection } = doubleCsrf({
    getSecret: () => configService.get<string>('CSRF_SECRET_KEY'),
    getSessionIdentifier: (req) => '',
    cookieName: 'buyfinity.x-csrf-token',
    cookieOptions: {
      secure: configService.get<string>('NODE_ENV') === 'production',
      path: '/',
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    getTokenFromRequest: (req) => req.headers['x-csrf-token'],
  });

  app.use(doubleCsrfProtection);

  // Using Helmet for security
  app.use(
    helmet({
      contentSecurityPolicy: false,
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  // Global Error Handling
  app.useGlobalFilters(new HttpExceptionFilter());

  // Start the application
  await app.listen(Number(configService.get('PORT')) || 5222, () => {
    console.log(`🚀 Server is listening on ${configService.get('PORT')}`);
  });
}

bootstrap();
