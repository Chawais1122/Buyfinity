import { seedUsers } from './user.seed';

async function main() {
  console.log('Starting seeding process...');

  try {
    // Call individual seed functions
    await seedUsers();
  } catch (error) {
    console.error('Seeding error:', error);
  } finally {
    console.log('Seeding process completed.');
    process.exit(0);
  }
}

main().catch((e) => {
  console.error('Unexpected error in seeding process:', e);
  process.exit(1);
});
