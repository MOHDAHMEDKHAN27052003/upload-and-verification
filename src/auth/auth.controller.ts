// auth.controller.ts
import { Controller, Post, Body, HttpCode, Req, UnauthorizedException, Res } from '@nestjs/common';
import { SendOtpDto } from './dto/send-otp.dto.js';
import { VerifyOtpDto } from './dto/verify-otp.dto.js';
import { AuthService } from './services/auth.service.js';
import { TokenService } from './services/token.service.js';
import express from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
  ) {}

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
    this.tokenService.setAuthCookies(res, accessToken, refreshToken);
    return rest;
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Req() req: express.Request,
    @Res({ passthrough: true }) res: express.Response,
  ) {
    const oldRefreshToken = req.cookies?.refresh_token;
    if (!oldRefreshToken) {
      throw new UnauthorizedException('Missing refresh token');
    }

    const { accessToken, refreshToken } =
      await this.authService.rotateRefreshToken(oldRefreshToken);

    this.tokenService.setAuthCookies(res, accessToken, refreshToken);
    return { message: 'Token refreshed' };
  }
}