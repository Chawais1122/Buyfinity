import { SignUpDto } from 'src/auth/dto';
import { MAIL_MESSAGES } from 'src/common/errors';
import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, InternalServerErrorException } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private mailerService: MailerService) {}

  async sendConfirmationEmail(
    otp: string,
    subject: string,
    userPayload: SignUpDto,
  ) {
    try {
      await this.mailerService.sendMail({
        to: userPayload.email,
        from: '"BUYFINITY" <Chaudharyawais.pk@gmail.com>',
        subject,
        replyTo: '"No Reply" <Chaudharyawais.pk@gmail.com>',
        template: './confirmation',
        context: {
          name: `${userPayload.firstName} ${userPayload.lastName}`,
          subject,
          otp,
        },
      });
    } catch (error) {
      console.error(error);
      throw new InternalServerErrorException(MAIL_MESSAGES.EMAIL_SEND_FAILED);
    }
  }
}
