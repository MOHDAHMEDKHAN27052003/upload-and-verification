// auth.service.ts
import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { MailerService } from './mailer.service.js';
import * as crypto from 'crypto';
import { Otp, OtpDocument } from './schemas/otp.schema.js';
import { User, UserDocument } from './schemas/user.schema.js';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private mailerService: MailerService,
  ) {}

  async sendOtp(payload: { email: string }): Promise<{ message: string }> {
    const email = payload.email.toLowerCase().trim();

    // 1. Generate a secure 6-digit OTP
    const otp = crypto.randomInt(100000, 999999);
    const hashedOtp = this.hashOtp(otp);

    // 2. Save/Update OTP in MongoDB (upsert resets TTL)
    await this.otpModel.findOneAndUpdate(
      { email },
      { email, hashedOtp, createdAt: new Date() },
      { upsert: true, returnDocument: 'after' },
    );

    // 3. Send the email
    await this.mailerService.sendOtpEmail(email, otp);

    return { message: 'OTP sent successfully' };
  }

  async verifyOtp(payload: { email: string; otp: number }): Promise<{ message: string }> {
    const { email, otp } = payload;

    if (!email || !otp) {
      throw new BadRequestException('Email and OTP are required');
    }

    const normalizedEmail = email.toLowerCase().trim();

    // 1. Find the OTP record
    const record = await this.otpModel.findOne({ email: normalizedEmail });

    if (!record) {
      throw new BadRequestException('OTP not found or has expired');
    }

    // 2. Compare hashed OTP
    const hashedInput = this.hashOtp(otp);
    const storedBuf = Buffer.from(record.hashedOtp, 'hex');
    const inputBuf = Buffer.from(hashedInput, 'hex');

    const isValid =
      storedBuf.length === inputBuf.length &&
      crypto.timingSafeEqual(storedBuf, inputBuf);

    if (!isValid) {
      throw new BadRequestException('Invalid OTP');
    }

    // 3. Delete the OTP (single-use)
    await this.otpModel.deleteOne({ _id: record._id });

    // 4. Create user if not exists, otherwise return existing
    //    - New users default to 'student'
    //    - Existing users keep their current role (e.g., librarian)
    await this.userModel.findOneAndUpdate(
      { email: normalizedEmail },
      { $setOnInsert: { email: normalizedEmail, role: 'student' } },
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true },
    );

    // 5. (Optional) Issue a JWT here using user._id and user.role

    return { message: 'OTP verified successfully' };
  }

  private hashOtp(otp: number): string {
    const secret = process.env.OTP_HASH_SECRET;
    return crypto
      .createHmac('sha256', secret!)
      .update(otp.toString())
      .digest('hex');
  }
}