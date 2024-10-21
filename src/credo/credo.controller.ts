import { Body, Controller, Get, Logger, Post } from '@nestjs/common';
import { CredoService } from './credo.service';
import { ApiTags } from '@nestjs/swagger';
import { API_VERSION } from 'src/constants';
import { CreateAgentDto } from './dto/credo.dto';

@Controller(`${API_VERSION}/credo`)
@ApiTags('Credo')
export class CredoController {
  private readonly logger = new Logger(CredoController.name);
  private agentId: string;
  constructor(private readonly credoService: CredoService) {
    
  }
  @Post('start')
  async startAgent(@Body() createAgentDto: CreateAgentDto): Promise<string> {
    
    
    await this.credoService.createAgent(
      createAgentDto.name,
      createAgentDto.endpoint,
      createAgentDto.port
    )
    this.agentId = createAgentDto.name;
    return 'Agent started';
    // startAgent(createAgentDto);
  }

  @Get('invite')
  async createInvitation(): Promise<any> {
    return await this.credoService.createNewInvitation(this.agentId);
  }

  @Post('create-offer-oid4vc')
  async createCredentialOffer(
    @Body() offerdCredentials: string[]
  ): Promise<any> {

    return await this.credoService.createOID4VCCredentialOffer(this.agentId, offerdCredentials);
  }

  // requestAndStoreCredentials
  @Post('resolve-credentials-oid4vc')
  async resolveCredentials(
    @Body() credentialsString: string
  ): Promise<any> {
    return await this.credoService.resolveCredentialOffer(this.agentId, credentialsString);
  }

  
}
