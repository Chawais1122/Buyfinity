import { IsNotEmpty, IsString } from 'class-validator';

export class ActivateUserDto {
  @IsNotEmpty()
  @IsString()
  activationToken: string;

  @IsNotEmpty()
  @IsString()
  activationCode: string;
}
