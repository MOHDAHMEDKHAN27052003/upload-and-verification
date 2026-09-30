// token.service.ts
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserDocument } from '../schemas/user.schema.js';

@Injectable()
export class TokenService {
  constructor(private jwtService: JwtService) {}

  async generateAccessToken(user: UserDocument): Promise<string> {
    const payload = {
      sub: user._id.toString(),
      email: user.email,
      role: user.role,
    };

    return this.jwtService.signAsync(payload);
  }
}