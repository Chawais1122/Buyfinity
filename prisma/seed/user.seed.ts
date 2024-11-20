import * as bcrypt from 'bcrypt';
import { PrismaClient, Role } from '@prisma/client';

const prisma = new PrismaClient();

export async function seedUsers() {
  console.log('Seeding Users...');

  const users = [
    {
      email: 'admin@example.com',
      password: await bcrypt.hash('P@ssword123', 10),
      firstName: 'Admin',
      lastName: 'User',
      role: Role.ADMIN,
      data: {},
    },
    {
      email: 'buyer@example.com',
      password: await bcrypt.hash('P@ssword123', 10),
      firstName: 'Buyer',
      lastName: 'User',
      role: Role.BUYER,
      data: {},
    },
  ];

  for (const user of users) {
    const existingUser = await prisma.user.findUnique({
      where: { email: user.email },
    });
    if (!existingUser) {
      await prisma.user.create({ data: user });
    }
  }

  console.log('Users seeded.');
}
