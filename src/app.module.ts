import { Module } from "@nestjs/common";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { DbModule } from "./db/db.module";
import { CredoModule } from "./credo/credo.module";
import { QrcodeModule } from "./qrcode/qrcode.module";
import { MessageModule } from "./message/message.module";
import { LedgerModule } from "./ledger/ledger.module";
import { ConnectionsModule } from "./connections/connections.module";
import { Oid4vcController } from './oid4vc/oid4vc.controller';
import { Oid4vcModule } from './oid4vc/oid4vc.module';
import { Oid4vcService } from "./oid4vc/oid4vc.service";

@Module({
  imports: [
    DbModule,
    CredoModule,
    QrcodeModule,
    MessageModule,
    LedgerModule,
    ConnectionsModule,
    Oid4vcModule,
  ],
  controllers: [AppController, Oid4vcController],
  providers: [AppService, Oid4vcService],
})
export class AppModule {}
