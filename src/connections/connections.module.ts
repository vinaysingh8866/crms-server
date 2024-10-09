import { Module } from '@nestjs/common';
import { ConnectionsController } from './connections.controller';
import { ConnectionsService } from './connections.service';
import { CredoModule } from 'src/credo/credo.module';

@Module({
  controllers: [ConnectionsController],
  providers: [ConnectionsService],
  imports: [CredoModule],
})
export class ConnectionsModule {}
