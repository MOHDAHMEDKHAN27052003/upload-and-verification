import { Controller, Get, UseGuards, Req, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { UserService } from './user.service.js';

interface RequestWithUser extends Request {
  user: {
    userId: string;
  };
}

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('me')
  @UseGuards(AuthGuard('jwt'))
  async getCurrentUser(@Req() req: RequestWithUser) {
    if (!req.user) {
      throw new UnauthorizedException('No user found in request');
    }

    return this.userService.getCurrentUser(req.user.userId);
  }
}