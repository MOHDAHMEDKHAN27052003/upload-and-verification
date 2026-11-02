// auth.service.ts
import { BadRequestException, HttpException, HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { Otp, OtpDocument } from '../otp.schema.js';
import { User, UserDocument } from '../../user/user.schema.js';
import { MailerService } from './mailer.service.js';
import { TokenService } from './token.service.js';

export interface VerifyOtpResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Otp.name) private otpModel: Model<OtpDocument>,
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private mailerService: MailerService,
    private tokenService: TokenService,
  ) { }

  async sendOtp(payload: { email: string }): Promise<{ message: string }> {
    const email = payload.email.toLowerCase().trim();

    const COOLDOWN_SECONDS = 60;

    const existing = await this.otpModel.findOne({ email });

    if (existing) {
      const secondsSince =
        (Date.now() - existing.createdAt.getTime()) / 1000;

      if (secondsSince < COOLDOWN_SECONDS) {
        const retryIn = Math.ceil(COOLDOWN_SECONDS - secondsSince);
        throw new HttpException(
          `Please wait ${retryIn} seconds before requesting another OTP`,
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
    }

    const otp = crypto.randomInt(100000, 999999);
    const hashedOtp = this.tokenService.hashOtp(otp);

    await this.otpModel.findOneAndUpdate(
      { email },
      { email, hashedOtp, createdAt: new Date() },
      { upsert: true, returnDocument: 'after' },
    );

    await this.mailerService.sendOtpEmail(email, otp);

    return { message: 'OTP sent successfully' };
  }

  async verifyOtp(payload: { email: string; otp: number }): Promise<VerifyOtpResponse> {
    const { email, otp } = payload;

    if (!email || !otp) {
      throw new BadRequestException('Email and OTP are required');
    }

    const normalizedEmail = email.toLowerCase().trim();

    const record = await this.otpModel.findOne({ email: normalizedEmail });
    if (!record) {
      throw new BadRequestException('OTP not found or has expired');
    }

    const hashedInput = this.tokenService.hashOtp(otp);

    if (!this.tokenService.compareHashes(record.hashedOtp, hashedInput)) {
      throw new BadRequestException('Invalid OTP');
    }

    await this.otpModel.deleteOne({ _id: record._id });

    const user = await this.userModel.findOneAndUpdate(
      { email: normalizedEmail },
      { $setOnInsert: { email: normalizedEmail, role: 'student' } },
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true },
    );

    // Issue tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Hash the refresh token before storing
    const hashedRefreshToken = this.tokenService.hashToken(refreshToken);

    // Optional: cap the number of stored sessions (e.g., keep last 5)
    await this.userModel.updateOne(
      { _id: user._id },
      {
        $push: {
          hashedRefreshTokens: {
            $each: [hashedRefreshToken],
            $slice: -5, // keep only the 5 most recent tokens
          },
        },
      },
    );

    return {
      message: 'OTP verified successfully',
      accessToken,
      refreshToken,
    };
  }

  async rotateRefreshToken(oldRefreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    // 1. Verify the JWT signature + expiry (throws if invalid/expired)
    let payload: { sub: string };
    try {
      payload = this.tokenService.verifyRefreshToken(oldRefreshToken);
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // 2. Hash the incoming token and look for it in the user's active sessions
    const hashedOld = this.tokenService.hashToken(oldRefreshToken);
    const user = await this.userModel.findOne({
      _id: payload.sub,
      hashedRefreshTokens: hashedOld,
    });

    if (!user) {
      // Token was valid JWT but not in the DB → reuse detected.
      // Revoke ALL sessions for this user (defense against token theft).
      await this.userModel.updateOne(
        { _id: payload.sub },
        { $set: { hashedRefreshTokens: [] } },
      );
      throw new UnauthorizedException('Refresh token reuse detected');
    }

    // 3. Issue a fresh pair
    const accessToken = this.tokenService.generateAccessToken(user);
    const newRefreshToken = this.tokenService.generateRefreshToken(user);
    const hashedNew = this.tokenService.hashToken(newRefreshToken);

    // 4. Atomically swap the old token for the new one (rotation)
    await this.userModel.updateOne(
      { _id: user._id, hashedRefreshTokens: hashedOld },
      {
        $pull: { hashedRefreshTokens: hashedOld },
      },
    );
    await this.userModel.updateOne(
      { _id: user._id },
      {
        $push: {
          hashedRefreshTokens: {
            $each: [hashedNew],
            $slice: -5,
          },
        },
      },
    );

    return { accessToken, refreshToken: newRefreshToken };
  }

  async signOut(refreshToken: string | undefined): Promise<{ message: string }> {
    // If there's no refresh token cookie, there's nothing to invalidate.
    // (We still return success — sign-out should be idempotent.)
    if (!refreshToken) {
      return { message: 'Signed out successfully' };
    }

    // Verify the JWT so we know which user to update.
    // If it's invalid/expired, we can't identify the user — but we still
    // want to clear cookies, so swallow the error.
    let payload: { sub: string };
    try {
      payload = this.tokenService.verifyRefreshToken(refreshToken);
    } catch {
      return { message: 'Signed out successfully' };
    }

    const hashedToken = this.tokenService.hashToken(refreshToken);

    // Remove just THIS session from the user's active refresh tokens.
    // (Other devices stay logged in.)
    await this.userModel.updateOne(
      { _id: payload.sub },
      { $pull: { hashedRefreshTokens: hashedToken } },
    );

    return { message: 'Signed out successfully' };
  }
}