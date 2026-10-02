// user.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type UserRole = 'librarian' | 'student';

export type UserDocument = HydratedDocument<User>;

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, unique: true, lowercase: true, trim: true })
  email: string;

  @Prop({ required: true, enum: ['librarian', 'student'], default: 'student' })
  role: UserRole;

  @Prop({ type: [String], default: [], select: false })
  hashedRefreshTokens: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);