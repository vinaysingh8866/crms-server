import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Query,
} from '@nestjs/common';
import { ConnectionsService } from './connections.service';
import {
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { API_VERSION } from 'src/constants';
import { CredoService } from 'src/credo/credo.service';
import { ConnectionType } from '@credo-ts/core';
import {
  CreateAgentDto,
  CreateInvitationDto,
  IssueCredentialDto,
  ReceiveInvitationDto,
  SetupConnectionListenerDto,
} from 'src/credo/dto/credo.dto';

@ApiTags('Connections')
@Controller(`${API_VERSION}/connections`)
export class ConnectionsController {
  constructor(
    private readonly connectionsService: ConnectionsService,
    private readonly credoService: CredoService,
  ) {}

  /**
   * Retrieve all connections with optional pagination.
   */
  @Get()
  @ApiOperation({
    summary: 'Retrieve all connections with optional pagination',
  })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'next', required: false, type: String })
  @ApiQuery({ name: 'previous', required: false, type: String })
  @ApiOkResponse({ description: 'Successfully retrieved all connections' })
  findAll(
    @Query('limit') limit: number = 50,
    @Query('next') next?: string,
    @Query('previous') previous?: string,
  ) {
    if (next || previous) {
      const base64Query = next || previous;
      const decodedQuery = base64Query
        ? JSON.parse(Buffer.from(base64Query, 'base64').toString('utf-8'))
        : '';
      if (!decodedQuery.pagination) {
        decodedQuery.pagination = {};
      }
      decodedQuery.pagination.direction = next
        ? 'next'
        : previous
          ? 'previous'
          : '';
      decodedQuery.pagination.limit = limit;
      return this.connectionsService.findAll(decodedQuery);
    } else {
      return this.connectionsService.findAll({ pagination: { limit } });
    }
  }

  /**
   * Retrieve connections by state.
   */
  @Get('/state/:state')
  @ApiOperation({ summary: 'Retrieve connections by state' })
  @ApiOkResponse({ description: 'Successfully retrieved connections by state' })
  findByState(@Param('state') state: string) {
    return this.connectionsService.findAllByQuery({ state });
  }

  /**
   * Retrieve connections by label.
   */
  @Get('/label/:theirLabel')
  @ApiOperation({ summary: 'Retrieve connections by label' })
  @ApiOkResponse({ description: 'Successfully retrieved connections by label' })
  findByLabel(@Param('theirLabel') theirLabel: string) {
    return this.connectionsService.findAll({ filter: { theirLabel } });
  }

  /**
   * Retrieve connections by role.
   */
  @Get('/role/:role')
  @ApiOperation({ summary: 'Retrieve connections by role' })
  @ApiOkResponse({ description: 'Successfully retrieved connections by role' })
  findByRole(@Param('role') role: string) {
    return this.connectionsService.findAllByQuery({ role });
  }

  /**
   * Retrieve connection by connection ID.
   */
  @Get('/connection_id/:id')
  @ApiOperation({ summary: 'Retrieve connection by connection ID' })
  @ApiOkResponse({ description: 'Successfully retrieved connection by ID' })
  findByConnectionId(@Param('id') id: string) {
    return this.connectionsService.findById(id);
  }

  /**
   * Retrieve connection by DID.
   */
  @Get('/did/:did')
  @ApiOperation({ summary: 'Retrieve connection by DID' })
  @ApiOkResponse({ description: 'Successfully retrieved connection by DID' })
  findByDid(@Param('did') did: string) {
    return this.connectionsService.findByDid(did);
  }

  /**
   * Retrieve connection by thread ID.
   */
  @Get('/thread_id/:threadId')
  @ApiOperation({ summary: 'Retrieve connection by thread ID' })
  @ApiOkResponse({
    description: 'Successfully retrieved connection by thread ID',
  })
  findByThreadId(@Param('threadId') threadId: string) {
    return this.connectionsService.getByThreadId(threadId);
  }

  /**
   * Retrieve connection by invitation DID.
   */
  @Get('/invitation_did/:invitationDid')
  @ApiOperation({ summary: 'Retrieve connection by invitation DID' })
  @ApiOkResponse({
    description: 'Successfully retrieved connection by invitation DID',
  })
  findByInvitationDid(@Param('invitationDid') invitationDid: string) {
    return this.connectionsService.findByInvitationDid(invitationDid);
  }

  /**
   * Retrieve all connections by out of band ID.
   */
  @Get('/out_of_band_id/:outOfBandId')
  @ApiOperation({ summary: 'Retrieve all connections by out of band ID' })
  @ApiOkResponse({
    description: 'Successfully retrieved connections by out of band ID',
  })
  findAllByOutOfBandId(@Param('outOfBandId') outOfBandId: string) {
    return this.connectionsService.findAllByOutOfBandId(outOfBandId);
  }

  /**
   * Retrieve all connections by connection types.
   */
  @Get('/connection_types/:connectionTypes')
  @ApiOperation({ summary: 'Retrieve all connections by connection types' })
  @ApiOkResponse({
    description: 'Successfully retrieved connections by connection types',
  })
  findAllByConnectionTypes(
    @Param('connectionTypes') connectionTypes: Array<ConnectionType | string>,
  ) {
    return this.connectionsService.findAllByConnectionTypes(connectionTypes);
  }

  /**
   * Retrieve connections by metadata.
   */
  @Get('/metadata/:key/:value')
  @ApiOperation({ summary: 'Retrieve connections by metadata' })
  @ApiOkResponse({
    description: 'Successfully retrieved connections by metadata',
  })
  findByMetadata(@Param('key') key: string, @Param('value') value: string) {
    return this.connectionsService.findAll({
      filter: { metadata: { key, value } },
    });
  }

  /**
   * Setup connection listener.
   */
  @Get('setup-connection-listener/:agentName/:outOfBandRecordId')
  @ApiOperation({ summary: 'Setup Connection Listener' })
  @ApiOkResponse({ description: 'Successfully setup connection listener' })
  async setupConnectionListener(@Param() params: SetupConnectionListenerDto) {
    const { agentName, outOfBandRecordId } = params;
    const agent = this.credoService.getAgentByName(agentName);
    const outOfBandRecord =
      await this.credoService.getOutOfBandRecordById(outOfBandRecordId);
    if (agent && outOfBandRecord) {
      this.credoService.setupConnectionListener(
        agent,
        outOfBandRecord,
        () => {},
      );
    }
  }

  /**
   * Create new invitation.
   */
  @Post('create-new-invitation')
  @ApiOperation({ summary: 'Create New Invitation' })
  @ApiOkResponse({ description: 'Successfully created new invitation' })
  async createNewInvitation(@Body() createInvitationDto: CreateInvitationDto) {
    const { agentName } = createInvitationDto;
    const agent = await this.credoService.createNewInvitation(agentName);
    if (agent) {
      const { invitationUrlQRcode } = agent;
      return { invitationUrlQRcode };
    }
  }

  /**
   * Create legacy invitation.
   */
  @Post('create-legacy-invitation')
  @ApiOperation({ summary: 'Create Legacy Invitation' })
  @ApiOkResponse({ description: 'Successfully created legacy invitation' })
  async createLegacyInvitation(
    @Body() createInvitationDto: CreateInvitationDto,
  ) {
    const { agentName } = createInvitationDto;
    const agent = await this.credoService.createLegacyInvitation(agentName);
    if (agent) {
      const { invitationUrl } = agent;
      return { invitationUrl };
    }
  }

  /**
   * Receive invitation.
   */
  @Post('receive-invitation')
  @ApiOperation({ summary: 'Receive Invitation' })
  @ApiOkResponse({ description: 'Successfully received invitation' })
  async receiveInvitation(@Body() receiveInvitationDto: ReceiveInvitationDto) {
    const { agentName, invitationUrl } = receiveInvitationDto;
    await this.credoService.receiveInvitation(agentName, invitationUrl);
  }

  /**
   * Issue credential.
   */
  @Post('issue-credential')
  @ApiOperation({ summary: 'Issue Credential' })
  @ApiOkResponse({ description: 'Successfully issued credential' })
  async issueCredential(@Body() issueCredentialDto: IssueCredentialDto) {
    const credentialExchangeRecord = await this.credoService.issueCredential(
      issueCredentialDto.connectionId,
      issueCredentialDto.credentialDefinitionId,
      issueCredentialDto.attributes,
    );
    return { credentialExchangeRecord };
  }

  /**
   * Create agent.
   */
  // @Post('create-agent/:name/:endpoint/:port')
  // @ApiOperation({ summary: 'Create Agent' })
  // @ApiOkResponse({ description: 'Successfully created agent' })
  // async createAgent(@Param() params: CreateAgentDto) {
  //   const { name, endpoint, port } = params;
  //   await this.credoService.createAgent(name, endpoint, port);
  // }

  /**
   * Delete connection by ID.
   */
  @Delete(':connectionId')
  @ApiOperation({ summary: 'Delete connection by ID' })
  @ApiOkResponse({ description: 'Successfully deleted connection by ID' })
  async deleteById(@Param('connectionId') connectionId: string) {
    return this.connectionsService.deleteById(connectionId);
  }
}
