import { Body, Controller, Post } from "@nestjs/common";
import { Oid4vcService } from "./oid4vc.service";
import { CredoService } from "src/credo/credo.service";
import { API_VERSION } from "src/constants";

@Controller(`${API_VERSION}/oid4vc`)
export class Oid4vcController {
  constructor(
    private readonly oid4vcService: Oid4vcService,
  ) {}
  @Post("create-offer-oid4vc")
  async createCredentialOffer(
    @Body() offerdCredentials: string[]
  ): Promise<any> {
    return await this.oid4vcService.createOIDCredentialOffer(offerdCredentials);
  }

  // requestAndStoreCredentials
  @Post("resolve-credentials-oid4vc")
  async resolveCredentials(@Body() credentialsString: string): Promise<any> {
    return await this.oid4vcService.resolveOIDCredentialOffer(
      credentialsString
    );
  }
}
