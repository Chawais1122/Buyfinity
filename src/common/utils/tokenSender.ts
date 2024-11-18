import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserTokenPayload } from 'src/auth/dto';

export class TokenSender {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  public createAccessToken(user: UserTokenPayload) {
    try {
      const accessToken = this.jwtService.sign(
        {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        },
        {
          secret: this.configService.get<string>('JWT_ACCESS_TOKEN_SECRET'),
          expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRE_IN'),
        },
      );
      return { ...user, accessToken };
    } catch (error) {
      throw error;
    }
  }

  public async createRefreshToken(user: UserTokenPayload) {
    try {
      const refreshToken = this.jwtService.sign(
        {
          id: user.id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
          expiresIn: this.configService.get('JWT_REFRESH_TOKEN_EXPIRE_IN'),
        },
      );
      return { refreshToken };
    } catch (error) {
      throw error;
    }
  }
}
