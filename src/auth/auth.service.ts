import * as bcrypt from 'bcrypt';
import * as csrf from 'csrf';
import { ActivateUserDto, LoginDto, SignUpDto } from './dto';
import {
  JsonWebTokenError,
  JwtService,
  JwtVerifyOptions,
  TokenExpiredError,
} from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AUTH_ERRORS, CSRF_ERRORS } from 'src/common/errors';
import { MailService } from 'src/mail/mail.service';
import { PrismaService } from 'prisma/prisma.service';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { TokenSender } from 'src/common/utils/tokenSender';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  private tokens = new csrf();
  constructor(
    private jwt: JwtService,
    private prisma: PrismaService,
    private config: ConfigService,
    private mailService: MailService,
  ) {}

  async signUp(signupDto: SignUpDto) {
    try {
      const { email, password, firstName, lastName, address } = signupDto;

      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new ConflictException(AUTH_ERRORS.EMAIL_ALREADY_EXISTS);
      }

      const hashedPassword = await bcrypt.hash(
        password,
        parseInt(this.config.get('SALT_ROUNDS')),
      );

      const userPayload = {
        email,
        address,
        lastName,
        firstName,
        password: hashedPassword,
      };

      const { activationToken, activationCode } =
        await this.generateActivationToken(userPayload);

      await this.mailService.sendConfirmationEmail(
        activationCode,
        'Confirmation Email',
        userPayload,
      );

      return { activationToken };
    } catch (error) {
      throw error;
    }
  }

  async generateActivationToken(user: SignUpDto) {
    try {
      const activationCode = Math.floor(
        100000 + Math.random() * 900000,
      ).toString();

      const activationToken = await this.jwt.sign(
        {
          user,
          activationCode,
        },
        {
          secret: this.config.get<string>('JWT_ACTIVATION_TOKEN_SECRET'),
          expiresIn: this.config.get('JWT_ACTIVATION_TOKEN_EXPIRE_IN'),
        },
      );

      return { activationToken, activationCode };
    } catch (error) {
      throw error;
    }
  }

  async activateUser(activateUserDto: ActivateUserDto) {
    try {
      const { activationToken, activationCode } = activateUserDto;

      const userPayload: { user: SignUpDto; activationCode: string } =
        this.jwt.verify(activationToken, {
          secret: this.config.get<string>('JWT_ACTIVATION_TOKEN_SECRET'),
        } as JwtVerifyOptions) as {
          user: SignUpDto;
          activationCode: string;
        };

      if (userPayload.activationCode !== activationCode) {
        throw new BadRequestException(AUTH_ERRORS.INVALID_ACTIVATION_CODE);
      }

      const { firstName, lastName, email, password, address } =
        userPayload.user;

      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new ConflictException(AUTH_ERRORS.EMAIL_ALREADY_EXISTS);
      }

      const createdUser = await this.prisma.user.create({
        data: {
          firstName,
          lastName,
          email,
          password,
          address,
        },
        select: {
          firstName: true,
          lastName: true,
          email: true,
          address: true,
        },
      });

      return createdUser;
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException(AUTH_ERRORS.TOKEN_EXPIRED);
      } else if (error instanceof JsonWebTokenError) {
        throw new UnauthorizedException(AUTH_ERRORS.INVALID_TOKEN);
      }
      throw error;
    }
  }

  private async comparePassword(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashedPassword);
  }

  async login(loginDto: LoginDto, req: Request, res: Response) {
    try {
      const { email, password } = loginDto;

      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (user && (await this.comparePassword(password, user.password))) {
        const tokenSender = new TokenSender(this.config, this.jwt);
        const { id, firstName, lastName, email } = user;

        this.setCsrfToken(req, res);

        const response = tokenSender.sendUserToken({
          id: id.toString(),
          firstName,
          lastName,
          email,
        });

        return res.json(response);
      } else {
        throw new ForbiddenException(AUTH_ERRORS.INVALID_CREDENTIALS);
      }
    } catch (error) {
      throw error;
    }
  }

  setCsrfToken(req: Request, res: Response) {
    try {
      // Generate CSRF secret if not already present in session
      if (!req.session.csrfSecret) {
        req.session.csrfSecret = this.tokens.secretSync();
      }

      // Create CSRF token
      const csrfToken = this.tokens.create(req.session.csrfSecret);

      // Set the CSRF token in a cookie
      res.cookie('buyfinity.x-csrf-token', csrfToken, {
        secure: this.config.get<string>('NODE_ENV') === 'production',
        httpOnly: true,
        path: '/',
      });

      return { message: CSRF_ERRORS.TOKEN_SET };
    } catch (error) {
      throw error;
    }
  }
}
