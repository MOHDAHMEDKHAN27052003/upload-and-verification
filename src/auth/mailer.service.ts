import { Injectable } from '@nestjs/common';
import { BrevoClient } from '@getbrevo/brevo';

@Injectable()
export class MailerService {
  private brevo: BrevoClient;

  constructor() {
    this.brevo = new BrevoClient({
      apiKey: process.env.BREVO_API_KEY!,
    });
  }

  async sendOtpEmail(to: string, otp: number) {
    try {
      await this.brevo.transactionalEmails.sendTransacEmail({
        subject: 'Verification OTP',
        to: [{ email: to }],
        htmlContent: `Your verification OTP: ${otp}`,
        sender: {
          name: 'Upload and verification',
          email: process.env.EMAIL,
        },
      });
    } catch (error) {
      console.error('Error sending OTP email via Brevo:', error);
      throw new Error('Failed to send OTP email');
    }
  }
}