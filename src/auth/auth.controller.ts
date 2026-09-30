// auth.controller.ts
import { Controller, Post, Body, HttpCode, Res } from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './services/auth.service.js';
import { SendOtpDto } from './dto/send-otp.dto.js';
import { VerifyOtpDto } from './dto/verify-otp.dto.js';

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
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, user } = await this.authService.verifyOtp(dto);

    res.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // use 'none' + secure:true if frontend is on a different domain
      maxAge: 1000 * 60 * 15,
      path: '/',
    });

    // Return the user, but omit the token from the body
    return { user };
  }
}