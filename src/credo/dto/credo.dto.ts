import {
  IsString,
  IsArray,
  ArrayNotEmpty,
  ValidateNested,
  IsInt,
} from "class-validator";
import { ApiProperty } from "@nestjs/swagger";
import { Type } from "class-transformer";
import { OpenId4VciResolvedCredentialOffer } from "@credo-ts/openid4vc";

export class ReceiveInvitationDto {
  @IsString()
  @ApiProperty({
    description: "Name of the agent who wants to receive the link",
    example: "agent1",
  })
  agentName: string;

  @IsString()
  @ApiProperty({
    description: "URL of the invitation",
    example: "https://example.com/invitation",
  })
  invitationUrl: string;
}

export class CreateInvitationDto {
  @IsString()
  @ApiProperty({
    description: "Name of the agent",
    example: "agent1",
  })
  agentName: string;
}

class CredentialAttribute {
  @IsString()
  @ApiProperty({
    description: "Attribute name",
    example: "name",
  })
  name: string;

  @IsString()
  @ApiProperty({
    description: "Attribute value",
    example: "Jane Doe",
  })
  value: string;
}

export class IssueCredentialDto {
  @IsString()
  @ApiProperty({
    description: "Connection ID",
    example: "12345",
  })
  connectionId: string;

  @IsString()
  @ApiProperty({
    description: "Credential Definition ID",
    example: "credDef123",
  })
  credentialDefinitionId: string;

  @IsArray()
  @ArrayNotEmpty()
  @ValidateNested({ each: true })
  @Type(() => CredentialAttribute)
  @ApiProperty({
    description: "Credential attributes",
    example: [
      { name: "name", value: "Jane Doe" },
      { name: "age", value: "23" },
    ],
  })
  attributes: CredentialAttribute[];
}

export class CreateAgentDto {
  @IsString()
  @ApiProperty({
    description: "Name of the agent",
    example: "agent1",
  })
  name: string;

  @IsString()
  @ApiProperty({
    description: "Endpoint of the agent",
    example: "http://localhost",
  })
  endpoint: string;

  @IsInt()
  @ApiProperty({
    description: "Port number for the agent",
    example: 3000,
  })
  port: number;

  @IsInt()
  @ApiProperty({
    description: "Port number for OID4VC service",
    example: 2000,
  })
  oid4vcPort: number;
}

export class SetupConnectionListenerDto {
  @IsString()
  @ApiProperty({
    description: "Name of the agent",
    example: "agent1",
  })
  agentName: string;

  @IsString()
  @ApiProperty({
    description: "ID of the Out-of-Band record",
    example: "outOfBandRecordId123",
  })
  outOfBandRecordId: string;
}

export class CreateCredentialOfferDto {
  @IsArray()
  @ArrayNotEmpty()
  @ApiProperty({
    description: "List of credential names to offer",
    example: ["UniversityDegreeCredential"],
  })
  offerdCredentials: string[];
}

// @Body() credentialsString: string
export class ResolveCredentialsDto {
  @IsString()
  @ApiProperty({
    description: "Stringified credentials",
    example: "credentialsString",
  })
  credentialsString: string;
}
