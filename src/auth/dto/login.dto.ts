import { Transform } from 'class-transformer';
import { AUTH_ERRORS } from 'src/common/errors';
import { AUTH_CONSTANTS } from 'src/common/constant';
import { IsEmail, Matches, IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  @Transform(({ value }) => value.toLowerCase())
  email: string;

  @IsNotEmpty()
  @IsString()
  @Matches(AUTH_CONSTANTS.PASSWORD_REGEX_PATTERN, {
    message: AUTH_ERRORS.PASSWORD_INVALID_FORMAT,
  })
  password: string;
}

export interface UserTokenPayload {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
}
