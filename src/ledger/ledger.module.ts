import { Module } from '@nestjs/common';
import { LedgerController } from './ledger.controller';
import { LedgerService } from './ledger.service';
import { CredoModule } from 'src/credo/credo.module';

@Module({
  controllers: [LedgerController],
  providers: [LedgerService],
  imports: [CredoModule],
})
export class LedgerModule {}
