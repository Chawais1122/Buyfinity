import { PrismaClient } from '@prisma/client';
import { DATABASE_MESSAGES } from 'src/common/errors';
import { Injectable, OnModuleInit } from '@nestjs/common';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    try {
      await this.$connect();
      console.log(DATABASE_MESSAGES.CONNECTION_SUCCESS);
    } catch (error) {
      throw new Error(DATABASE_MESSAGES.CONNECTION_ERROR);
    }
  }
}
