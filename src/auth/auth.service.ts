// auth.service.ts
import { BadRequestException, Injectable } from '@nestjs/common';
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

  async verifyOtp(payload: { email: string; otp: number }): Promise<{ message: string }> {
    const { email, otp } = payload;

    if (!email || !otp) {
      throw new BadRequestException('Email and OTP are required');
    }

    // 1. Find the OTP record for this email
    const record = await this.otpModel.findOne({ email: email.toLowerCase().trim() });

    if (!record) {
      throw new BadRequestException('OTP not found or has expired');
    }

    // 2. Hash the incoming OTP using the same secret and compare
    const hashedInput = this.hashOtp(otp);

    // Use timingSafeEqual to prevent timing attacks
    const storedBuf = Buffer.from(record.hashedOtp, 'hex');
    const inputBuf = Buffer.from(hashedInput, 'hex');

    const isValid =
      storedBuf.length === inputBuf.length &&
      crypto.timingSafeEqual(storedBuf, inputBuf);

    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    // 3. Delete the OTP so it can't be reused (single-use)
    await this.otpModel.deleteOne({ _id: record._id });

    // 4. (Optional) Issue a JWT / mark the user verified here
    return { message: 'OTP verified successfully' };
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