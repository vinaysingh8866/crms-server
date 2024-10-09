import { IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateQrCodeDto {
  @IsString()
  @ApiProperty({
    description: 'The data to be encoded in the QR code',
    example: 'https://example.com',
  })
  data: string;
}
