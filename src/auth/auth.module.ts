// auth.module.ts
import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthController } from './auth.controller.js';
import { AuthService } from './services/auth.service.js';
import { MailerService } from './mailer.service.js';
import { Otp, OtpSchema } from './schemas/otp.schema.js';
import { User, UserSchema } from './schemas/user.schema.js';
import { JwtModule } from '@nestjs/jwt';
import { TokenService } from './services/token.service.js';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Otp.name, schema: OtpSchema },
      { name: User.name, schema: UserSchema },
    ]),
    JwtModule.register({}),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailerService, TokenService],
})
export class AuthModule { }