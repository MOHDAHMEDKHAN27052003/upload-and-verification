import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../auth/schemas/user.schema.js';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
  ) {}

  async getCurrentUser(userId: string) {
    const user = await this.userModel.findById(userId).exec();

    if (!user) {
      throw new NotFoundException('User not found');
    }
    return {user};
  }
}