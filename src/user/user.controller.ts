import { Controller, Post, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard, RolesGuard } from 'src/auth/guard';
import { GetUser } from 'src/auth/decorators';
import { User } from '@prisma/client';

@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('profile')
  getProfile(@GetUser() user: User) {
    return user;
  }
}
