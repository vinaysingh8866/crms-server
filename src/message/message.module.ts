import { Module } from '@nestjs/common';
import { MessageController } from './message.controller';
import { MessageService } from './message.service';
import { CredoModule } from 'src/credo/credo.module';

@Module({
  controllers: [MessageController],
  providers: [MessageService],
  imports: [CredoModule],
})
export class MessageModule {}
