import { ApiProperty } from '@nestjs/swagger';

export class ImportDidDto {
  @ApiProperty({
    description: 'Seed for the DID',
    example: '0000000000000000000000000Forward',
  })
  seed: string;

  @ApiProperty({
    description: 'DID to import',
    example: 'did:indy:bcovrin:test:123456789abcdefghi',
  })
  did: string;
}

export class RegisterSchemaDto {
  @ApiProperty({
    description: 'DID of the issuer',
    example: 'did:indy:bcovrin:test:123456789abcdefghi',
  })
  did: string;

  @ApiProperty({
    description: 'Schema name',
    example: 'Example Schema',
  })
  schemaName: string;

  @ApiProperty({
    description: 'Schema version',
    example: '1.0.0',
  })
  version: string;

  @ApiProperty({
    description: 'Schema attributes',
    example: ['email', 'age', 'name'],
  })
  attrNames: string[];
}

export class RegisterCredentialDefinitionDto {
  @ApiProperty({
    description: 'DID of the issuer',
    example: 'did:indy:bcovrin:test:123456789abcdefghi',
  })
  did: string;

  @ApiProperty({
    description: 'Schema ID',
    example: 'schema:id',
  })
  schemaId: string;
}
