import * as bcrypt from 'bcrypt';
import * as csrf from 'csrf';
import { ActivateUserDto, LoginDto, ResetPasswordDto, SignUpDto } from './dto';
import {
  JsonWebTokenError,
  JwtService,
  JwtVerifyOptions,
  TokenExpiredError,
} from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AUTH_MESSAGES, CSRF_MESSAGES } from 'src/common/errors';
import { MailService } from 'src/mail/mail.service';
import { PrismaService } from 'prisma/prisma.service';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { TokenSender } from 'src/common/utils/tokenSender';
import { Request, Response } from 'express';
import { AllowedRoles } from 'src/common/constant';

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
      const { email, password, firstName, lastName, address, role } = signupDto;

      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new ConflictException(AUTH_MESSAGES.EMAIL_ALREADY_EXISTS);
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
        role,
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
      console.log(error);
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
      console.log(error);
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
        throw new BadRequestException(AUTH_MESSAGES.INVALID_ACTIVATION_CODE);
      }

      const { firstName, lastName, email, password, address } =
        userPayload.user;

      const user = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (user) {
        throw new ConflictException(AUTH_MESSAGES.EMAIL_ALREADY_EXISTS);
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
      console.log(error);
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException(AUTH_MESSAGES.TOKEN_EXPIRED);
      } else if (error instanceof JsonWebTokenError) {
        throw new UnauthorizedException(AUTH_MESSAGES.INVALID_TOKEN);
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
        const { id, firstName, lastName, email, role } = user;

        this.setCsrfToken(req, res);

        const response = await tokenSender.createAccessToken({
          id: id.toString(),
          firstName,
          lastName,
          email,
          role,
        });

        const { refreshToken } = await tokenSender.createRefreshToken({
          id: id.toString(),
          firstName,
          lastName,
          email,
          role,
        });

        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: this.config.get<string>('NODE_ENV') === 'production',
          path: '/',
        });

        return res.json(response);
      } else {
        throw new ForbiddenException(AUTH_MESSAGES.INVALID_CREDENTIALS);
      }
    } catch (error) {
      console.log(error);
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

      return { message: CSRF_MESSAGES.TOKEN_SET };
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  async refreshAccessToken(req: Request, res: Response) {
    try {
      const refreshToken = req.cookies['refreshToken'];
      if (!refreshToken)
        throw new UnauthorizedException(AUTH_MESSAGES.INVALID_TOKEN);

      const user = await this.jwt.verify(refreshToken, {
        secret: this.config.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      });
      const tokenSender = new TokenSender(this.config, this.jwt);
      const accessToken = await tokenSender.createAccessToken(user);

      return res.json(accessToken);
    } catch (error) {
      console.log(error);
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException(AUTH_MESSAGES.TOKEN_EXPIRED);
      } else if (error instanceof JsonWebTokenError) {
        throw new UnauthorizedException(AUTH_MESSAGES.INVALID_TOKEN);
      }
      throw error;
    }
  }

  async forgotPassword(email: string) {
    try {
      const user = await this.prisma.user.findUnique({ where: { email } });
      if (!user) {
        throw new NotFoundException(AUTH_MESSAGES.USER_NOT_FOUND);
      }

      const code = Math.floor(100000 + Math.random() * 900000).toString();

      const resetToken = await this.jwt.signAsync(
        { id: user.id.toString(), email },
        {
          secret: this.config.get<string>('JWT_RESET_PASSWORD_SECRET'),
          expiresIn: this.config.get<string>('JWT_RESET_TOKEN_EXPIRE_IN'),
        },
      );

      const hashedResetToken = await bcrypt.hash(
        resetToken,
        parseInt(this.config.get('SALT_ROUNDS')),
      );

      await this.prisma.user.update({
        where: { email },
        data: {
          data: {
            code,
            resetPasswordToken: hashedResetToken,
            resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes from now
          },
        },
      });

      const userPayload = {
        email,
        lastName: user.lastName,
        firstName: user.firstName,
        password: user.password,
        role: user.role as AllowedRoles,
      };

      await this.mailService.sendConfirmationEmail(
        code,
        'Password Reset Request',
        userPayload,
      );

      return { resetToken, message: AUTH_MESSAGES.OTP_SENT };
    } catch (error) {
      console.log(error);
      throw error;
    }
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    try {
      const { token, code, newPassword } = resetPasswordDto;

      const payload = this.jwt.verify(token, {
        secret: this.config.get<string>('JWT_RESET_PASSWORD_SECRET'),
      });

      const user = await this.prisma.user.findUnique({
        where: { email: payload.email },
      });

      if (!user) {
        throw new BadRequestException(AUTH_MESSAGES.INVALID_TOKEN);
      }

      const isTokenValid = await bcrypt.compare(
        token,
        (user.data as any).resetPasswordToken,
      );

      if (
        !isTokenValid ||
        (user.data as any).resetPasswordExpires < new Date()
      ) {
        throw new BadRequestException(AUTH_MESSAGES.TOKEN_EXPIRED);
      }

      if (code !== (user.data as any).code) {
        throw new BadRequestException(AUTH_MESSAGES.INVALID_OTP_CODE);
      }

      const hashedPassword = await bcrypt.hash(
        newPassword,
        parseInt(this.config.get('SALT_ROUNDS')),
      );

      await this.prisma.user.update({
        where: { email: user.email },
        data: {
          password: hashedPassword,
        },
      });

      return { message: AUTH_MESSAGES.PASSWORD_RESET_SUCCESS };
    } catch (error) {
      console.log(error);
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException(AUTH_MESSAGES.TOKEN_EXPIRED);
      } else if (error instanceof JsonWebTokenError) {
        throw new BadRequestException(AUTH_MESSAGES.INVALID_TOKEN);
      }
      throw error;
    }
  }
}
