import { Controller, Get, Query } from '@nestjs/common';
import { QrcodeService } from './qrcode.service';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CreateQrCodeDto } from './dto/create-qrcode.dto';
import { API_VERSION } from 'src/constants';

@Controller(`${API_VERSION}/qrcode`)
@ApiTags('QR Code')
export class QrcodeController {
  constructor(private readonly qrCodeService: QrcodeService) {}

  @Get()
  @ApiOperation({ summary: 'Generate QR Code' })
  @ApiOkResponse({ description: 'Successfully generated QR code' })
  async generateQrCode(@Query() query: CreateQrCodeDto) {
    const qrCodeDataURL = await this.qrCodeService.generateQrCode(query.data);
    return `<img src="${qrCodeDataURL}" alt="QR Code" />`;
  }
}
