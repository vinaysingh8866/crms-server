import { ApiProperty } from '@nestjs/swagger';

export class SendMessageDto {
  @ApiProperty({
    description: 'The ID of the connection to send the message to',
    example: '12345',
  })
  connectionId: string;

  @ApiProperty({
    description: 'The content of the message to be sent',
    example: 'Hello, this is a test message',
  })
  message: string;
}
