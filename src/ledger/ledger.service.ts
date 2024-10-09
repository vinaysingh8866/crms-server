import { KeyType, TypedArrayEncoder } from '@credo-ts/core';
import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { CredoService } from 'src/credo/credo.service';

@Injectable()
export class LedgerService {
  private readonly logger = new Logger(LedgerService.name);

  constructor(private readonly credoService: CredoService) {}

  /**
   * Import a DID (Decentralized Identifier) into the agent
   *
   * @param seed - The seed string used to generate the private key
   * @param did - The DID to import
   * @returns A success message upon successful import
   */
  async importDid(seed: string, did: string) {
    if (!this.credoService.agent) {
      this.logger.error(`[importDid] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      const privateKey = TypedArrayEncoder.fromString(seed);
      await this.credoService.agent.dids.import({
        did: did,
        overwrite: true,
        privateKeys: [
          {
            privateKey: privateKey,
            keyType: KeyType.Ed25519,
          },
        ],
      });
      this.logger.log(
        `[importDid] Success: DID ${did} successfully imported with seed ${seed}`,
      );
      return `DID ${did} successfully imported with seed ${seed}`;
    } catch (error) {
      this.logger.error(`[importDid] Error: Failed to import DID ${did}`);
      throw error;
    }
  }

  /**
   * Register a new schema
   *
   * @param did - DID of the schema issuer
   * @param schemaName - Name of the schema
   * @param version - Version of the schema
   * @param attrNames - Array of attribute names in the schema
   * @returns The ID of the registered schema
   */
  async registerSchema(
    did: string,
    schemaName: string,
    version: string,
    attrNames: string[],
  ): Promise<string> {
    if (!this.credoService.agent) {
      this.logger.error(`[registerSchema] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      const schemaResult =
        await this.credoService.agent.modules.anoncreds.registerSchema({
          schema: {
            attrNames,
            issuerId: did,
            name: schemaName,
            version,
          },
          options: {},
        });
      if (schemaResult.schemaState.state === 'failed') {
        throw new Error(
          `Error creating schema: ${schemaResult.schemaState.reason}`,
        );
      }
      this.logger.log(
        `[registerSchema] Registered schema: ${schemaResult.schemaState.schemaId}`,
      );
      return schemaResult.schemaState.schemaId;
    } catch (error) {
      this.logger.error(`[registerSchema] Error: Failed to register schema.`);
      throw error;
    }
  }

  /**
   * Register a Credential Definition
   *
   * @param did - Decentralized Identifier of the issuer
   * @param schemaId - Schema ID associated with the credential definition
   * @returns The ID of the registered credential definition
   * @throws Error if the registration fails
   */
  async registerCredentialDefinition(
    did: string,
    schemaId: string,
  ): Promise<string> {
    if (!this.credoService.agent) {
      this.logger.error(`[registerSchema] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      const credentialDefinitionResult =
        await this.credoService.agent.modules.anoncreds.registerCredentialDefinition(
          {
            credentialDefinition: {
              tag: 'default',
              issuerId: did,
              schemaId,
            },
            options: {
              supportRevocation: false,
            },
          },
        );
      if (
        credentialDefinitionResult.credentialDefinitionState.state === 'failed'
      ) {
        throw new Error(
          `Error creating credential definition: ${credentialDefinitionResult.credentialDefinitionState.reason}`,
        );
      }
      this.logger.log(
        `[registerCredentialDefinition] Registered Credential Definition: ${credentialDefinitionResult.credentialDefinitionState.credentialDefinitionId}`,
      );
      return credentialDefinitionResult.credentialDefinitionState
        .credentialDefinitionId;
    } catch (error) {
      this.logger.error(`Failed to register credential definition.`);
      throw error;
    }
  }
}
