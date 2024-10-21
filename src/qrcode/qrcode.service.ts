import { Injectable } from '@nestjs/common';
import * as qrcode from 'qrcode';

@Injectable()
export class QrcodeService {
  async generateQrCode(data: string): Promise<string> {
    console.log('Generating QR code');
    console.log(data);
    try {
      const qrCodeDataURL = await qrcode.toDataURL(data);
      return qrCodeDataURL;
    } catch (error) {
      throw new Error('Failed to generate QR code.');
    }
  }
}
