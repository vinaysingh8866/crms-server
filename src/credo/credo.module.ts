import { Module } from '@nestjs/common';
import { CredoController } from './credo.controller';
import { CredoService } from './credo.service';
import { QrcodeService } from 'src/qrcode/qrcode.service';

@Module({
  controllers: [CredoController],
  providers: [CredoService, QrcodeService],
  exports: [CredoService],
})
export class CredoModule {}
