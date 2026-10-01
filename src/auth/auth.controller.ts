// auth.controller.ts
import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { SendOtpDto } from './dto/send-otp.dto.js';
import { VerifyOtpDto } from './dto/verify-otp.dto.js';
import { AuthService } from './services/auth.service.js';
import { Res } from '@nestjs/common';
import express from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('send-otp')
  async sendOtp(@Body() sendOtpDto: SendOtpDto) {
    return this.authService.sendOtp(sendOtpDto);
  }

  @Post('verify-otp')
  @HttpCode(200)
  async verifyOtp(
    @Body() dto: VerifyOtpDto,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const { accessToken, refreshToken, ...rest } = await this.authService.verifyOtp(dto);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
      sameSite: 'lax', // or 'strict' / 'none' depending on your frontend/backend domains
      maxAge: 15 * 60 * 1000, // 15 min — match your access token TTL
      path: '/',
    });

    // Optionally also set refresh token as a cookie (recommended)
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/auth/refresh', // scope it to the refresh endpoint only
    });

    return rest; // { message: 'OTP verified successfully' }
  }
}