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
      createAgentDto.port,
      createAgentDto.oid4vcPort
    )
    this.agentId = createAgentDto.name;
    return 'Agent started';
    // startAgent(createAgentDto);
  }

  @Get('invite')
  async createInvitation(): Promise<any> {
    return await this.credoService.createNewInvitation(this.agentId);
  }

  
}
