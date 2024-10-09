import { Body, Controller, Post } from '@nestjs/common';
import { LedgerService } from './ledger.service';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import {
  ImportDidDto,
  RegisterCredentialDefinitionDto,
  RegisterSchemaDto,
} from './dto/ledger.dto';
import { API_VERSION } from 'src/constants';

@ApiTags('Ledger')
@Controller(`${API_VERSION}/ledger`)
export class LedgerController {
  constructor(private readonly ledgerService: LedgerService) {}

  /**
   * Endpoint to import a DID (Decentralized Identifier)
   *
   * @param importDidDto - DTO containing the seed and DID to import
   * @returns A confirmation message indicating the result of the import operation
   */
  @Post('import-did')
  @ApiOperation({
    summary: 'Import a DID',
    description:
      'Imports a Decentralized Identifier (DID) using the provided seed and DID.',
  })
  @ApiResponse({ status: 201, description: 'DID successfully imported.' })
  @ApiResponse({ status: 404, description: 'Agent is not initialized.' })
  async importDid(@Body() importDidDto: ImportDidDto) {
    const confirmationMessage = await this.ledgerService.importDid(
      importDidDto.seed,
      importDidDto.did,
    );
    return { message: confirmationMessage };
  }

  /**
   * Endpoint to register a new schema
   *
   * @param registerSchemaDto - DTO containing the DID, schema name, version, and attribute names
   * @returns The ID of the registered schema
   */
  @Post('register-schema')
  @ApiOperation({
    summary: 'Register a new schema',
    description:
      'Registers a new schema with the provided DID, schema name, version, and attribute names.',
  })
  @ApiResponse({ status: 201, description: 'Schema successfully registered.' })
  async registerSchema(@Body() registerSchemaDto: RegisterSchemaDto) {
    const schemaId = await this.ledgerService.registerSchema(
      registerSchemaDto.did,
      registerSchemaDto.schemaName,
      registerSchemaDto.version,
      registerSchemaDto.attrNames,
    );
    return { schemaId };
  }

  /**
   * Register a Credential Definition
   *
   * @param registerCredentialDefinitionDto - DTO containing the DID and Schema ID
   * @returns Object containing the registered credential definition ID
   */
  @Post('register-credential-definition')
  @ApiOperation({ summary: 'Register Credential Definition' })
  @ApiResponse({
    status: 201,
    description: 'Successfully registered credential definition',
  })
  async registerCredentialDefinition(
    @Body() registerCredentialDefinitionDto: RegisterCredentialDefinitionDto,
  ) {
    const credentialDefinitionId =
      await this.ledgerService.registerCredentialDefinition(
        registerCredentialDefinitionDto.did,
        registerCredentialDefinitionDto.schemaId,
      );
    return { credentialDefinitionId };
  }
}
