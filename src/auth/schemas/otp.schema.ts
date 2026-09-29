// otp.schema.ts
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import * as validator from 'validator'; // Optional for email validation

export type OtpDocument = Otp & Document;

@Schema()
export class Otp {
  @Prop({
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: (email: string) => validator.isEmail(email),
      message: 'Please provide a valid email address.',
    },
  })
  email: string;

  @Prop({ required: true })
  hashedOtp: string;

  // TTL index: MongoDB deletes this document 300 seconds (5 mins) after creation
  @Prop({ type: Date, default: Date.now, expires: 300 })
  createdAt: Date;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);