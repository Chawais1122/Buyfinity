import { ConfigService } from '@nestjs/config';
import { AUTH_MESSAGES } from 'src/common/errors';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'prisma/prisma.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class JwtAuthStrategy extends PassportStrategy(
  Strategy,
  'jwt-auth-strategy',
) {
  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
    });
  }

  async validate(payload: { id: string; email: string }): Promise<any> {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          id: payload.id,
        },
      });

      if (!user) {
        throw new UnauthorizedException(AUTH_MESSAGES.UNAUTHORIZED_USER);
      }
      return user;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException(AUTH_MESSAGES.TOKEN_EXPIRED);
      }
      throw new UnauthorizedException(AUTH_MESSAGES.UNAUTHORIZED_USER);
    }
  }
}
