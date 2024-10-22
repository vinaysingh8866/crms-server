import { Module } from '@nestjs/common';
import { Oid4vcService } from './oid4vc.service';
import { Oid4vcController } from './oid4vc.controller';
import { CredoModule } from 'src/credo/credo.module';

@Module({
  providers: [Oid4vcService],
  controllers:[Oid4vcController],
  imports:[CredoModule]
})
export class Oid4vcModule {}
