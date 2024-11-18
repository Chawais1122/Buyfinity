import { Transform } from 'class-transformer';
import { AUTH_MESSAGES } from 'src/common/errors';
import { AUTH_CONSTANTS } from 'src/common/constant';
import { IsEmail, IsNotEmpty, IsString, Matches } from 'class-validator';

export class ForgotPasswordDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  @Transform(({ value }) => value.toLowerCase())
  email: string;
}

export class ResetPasswordDto {
  @IsNotEmpty()
  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  code: string;

  @IsNotEmpty()
  @IsString()
  @Matches(AUTH_CONSTANTS.PASSWORD_REGEX_PATTERN, {
    message: AUTH_MESSAGES.PASSWORD_INVALID_FORMAT,
  })
  newPassword: string;
}
