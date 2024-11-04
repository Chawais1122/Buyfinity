import { join } from 'path';
import { MailService } from './mail.service';
import { ConfigService } from '@nestjs/config';
import { Global, Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

@Global()
@Module({
  imports: [
    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          service: 'SendGrid',
          auth: {
            user: 'apikey',
            pass: config.get('SENDGRID_API_KEY'),
          },
        },
        defaults: {
          from: `"No Reply" <${config.get('MAIL_FROM') || 'Chaudharyawais.pk@gmail.com'}>`,
        },
        template: {
          dir: join(__dirname, 'templates/'),
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
