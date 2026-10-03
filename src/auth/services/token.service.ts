import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import express from 'express';
import { UserDocument } from '../schemas/user.schema.js';

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) { }

  generateAccessToken(user: UserDocument): string {
    return this.jwtService.sign(
      { sub: user._id.toString(), email: user.email, role: user.role },
      { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '15m' },
    );
  }

  generateRefreshToken(user: UserDocument): string {
    return this.jwtService.sign(
      { sub: user._id.toString(), email: user.email, role: user.role },
      { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '7d' },
    );
  }

  verifyRefreshToken(token: string): { sub: string; email: string; role: string } {
    return this.jwtService.verify(token, {
      secret: process.env.JWT_REFRESH_SECRET,
    });
  }

  setAuthCookies(
    res: express.Response,
    accessToken: string,
    refreshToken: string,
  ): void {
    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
      path: '/',
    });

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/auth/refresh',
    });
  }

  /**
   * Hash a token using SHA-256. Refresh tokens are already high-entropy
   * random strings, so a fast hash (SHA-256) is sufficient and avoids
   * the cost of bcrypt/argon2 on every request.
   */
  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Hash an OTP using HMAC-SHA256 with a server-side secret.
   * This ensures that even if the DB is leaked, OTPs can't be
   * brute-forced (only 10^6 possibilities) without the secret.
   */
  hashOtp(otp: number): string {
    const secret = process.env.OTP_HASH_SECRET;
    return crypto.createHmac('sha256', secret!).update(otp.toString()).digest('hex');
  }

  /**
   * Constant-time comparison of two hex-encoded hashes.
   * Returns false if lengths differ (crypto.timingSafeEqual would throw).
   */
  compareHashes(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
  }
}