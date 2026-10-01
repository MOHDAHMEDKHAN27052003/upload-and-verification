// token.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserDocument } from '../schemas/user.schema.js';

@Injectable()
export class TokenService {
  constructor(private readonly jwtService: JwtService) {}

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
}