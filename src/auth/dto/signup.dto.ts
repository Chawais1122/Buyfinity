import {
  IsEmail,
  Matches,
  IsString,
  MaxLength,
  IsOptional,
  IsNotEmpty,
  ValidateNested,
  IsEnum,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { AllowedRoles, AUTH_CONSTANTS } from 'src/common/constant';
import { AUTH_MESSAGES } from 'src/common/errors';

class AddressDto {
  @IsNotEmpty()
  @IsString()
  street: string;

  @IsNotEmpty()
  @IsString()
  city: string;

  @IsNotEmpty()
  @IsString()
  state: string;

  @IsNotEmpty()
  @IsString()
  zip: string;
}

export class SignUpDto {
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  @Transform(({ value }) => value.toLowerCase())
  email: string;

  @IsNotEmpty()
  @IsString()
  @Matches(AUTH_CONSTANTS.PASSWORD_REGEX_PATTERN, {
    message: AUTH_MESSAGES.PASSWORD_INVALID_FORMAT,
  })
  password: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(25)
  @Transform(({ value }) => value.trim())
  firstName: string;

  @IsNotEmpty()
  @IsString()
  @MaxLength(25)
  @Transform(({ value }) => value.trim())
  lastName: string;

  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => AddressDto)
  address?: AddressDto;

  @IsNotEmpty()
  @IsEnum(AllowedRoles)
  role: AllowedRoles;
}
