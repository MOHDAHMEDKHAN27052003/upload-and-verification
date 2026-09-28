// auth.service.ts
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Otp, OtpDocument } from './otp.schema.js';
import { MailerService } from './mailer.service.js';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
    private mailerService: MailerService,
  ) {}

  async sendOtp(payload: { email: string }): Promise<{ message: string }> {
    const { email } = payload;

    // 1. Generate a secure 6-digit OTP
    const otp = crypto.randomInt(100000, 999999);

    const hashedOtp = this.hashOtp(otp);

    // 2. Save/Update OTP in MongoDB
    // The "upsert" ensures we overwrite any existing OTP for this email
    // and the TTL index resets because we are saving a new document/updating it.
    await this.otpModel.findOneAndUpdate(
      { email },
      { 
        email, 
        hashedOtp, 
        createdAt: new Date() // Reset TTL timer
      },
      { upsert: true, returnDocument: 'after' }
    );

    // 3. Send the email via Brevo
    await this.mailerService.sendOtpEmail(email, otp);

    return { message: 'OTP sent successfully' };
  }

  private hashOtp(otp: number): string {
    // Use a server-side secret (from env) as a salt
    const secret = process.env.OTP_HASH_SECRET;
    
    return crypto
      .createHmac('sha256', secret!)
      .update(otp.toString())
      .digest('hex');
  }
}