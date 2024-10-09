import { Controller, Logger } from '@nestjs/common';
import { CredoService } from './credo.service';
import { ApiTags } from '@nestjs/swagger';

import { API_VERSION } from 'src/constants';

@Controller(`${API_VERSION}/credo`)
@ApiTags('Credo')
export class CredoController {
  private readonly logger = new Logger(CredoController.name);

  constructor(private readonly credoService: CredoService) {}
}
