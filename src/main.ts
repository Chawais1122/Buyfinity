import helmet from 'helmet';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import rateLimit from 'express-rate-limit';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import { csrfMiddleware } from './auth/middleware/csrf.middleware';
import Redis from 'ioredis';
import RedisStore from 'connect-redis';

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

  // Set up Redis client
  const redisClient = new Redis({
    host: configService.get<string>('REDIS_HOST') || '127.0.0.1',
    port: configService.get<number>('REDIS_PORT') || 6379,
    password: configService.get<string>('REDIS_PASSWORD') || undefined,
  });

  // Middleware for session management
  app.use(
    session({
      store: new RedisStore({ client: redisClient }),
      secret: configService.get<string>('SESSION_SECRET'),
      resave: false,
      saveUninitialized: true,
      cookie: {
        secure: configService.get<string>('NODE_ENV') === 'production', // Secure cookie in production
        maxAge: 1000 * 60 * 60 * 24, // 1 day
      },
    }),
  );

  // Enable global validation for CSRF using the guard approach
  app.use(csrfMiddleware());

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
