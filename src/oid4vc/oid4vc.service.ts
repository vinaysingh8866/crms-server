import { Agent, DifPresentationExchangeDefinitionV2, DifPresentationExchangeService } from '@credo-ts/core';
import { OpenId4VcSiopResolvedAuthorizationRequest } from '@credo-ts/openid4vc';
import { Injectable } from '@nestjs/common';
import { CredoService } from 'src/credo/credo.service';

@Injectable()
export class Oid4vcService {
    constructor(private readonly credoService: CredoService) {}

    public async createOIDCredentialOffer(
        offeredCredentials: string[]
      ) {
        const agent: Agent | undefined = this.credoService.agent;
        
        const { credentialOffer } =
          await agent.modules.openId4VcIssuer.createCredentialOffer({
            issuerId: this.credoService.issuerRecord.issuerId,
            offeredCredentials,
            preAuthorizedCodeFlowConfig: { userPinRequired: false },
          });
    
        return credentialOffer;
      }
    
      public async resolveOIDCredentialOffer(
        credentialOffer: string,
      ) {
        const agent = this.credoService.agent;
        return await agent.modules.openId4VcHolder.resolveCredentialOffer(
          credentialOffer
        );
      }
    
      public async resolveOIDProofRequest(proofRequest: string) {
        const agent = this.credoService.agent;
        
        const resolvedProofRequest =
          await agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
            proofRequest
          );
    
        return resolvedProofRequest;
      }
      public async acceptPresentationRequest(
        resolvedPresentationRequest: OpenId4VcSiopResolvedAuthorizationRequest,
      ) {
        const agent = this.credoService.agent
        
        const presentationExchangeService = agent.dependencyManager.resolve(
          DifPresentationExchangeService
        );
    
        if (!resolvedPresentationRequest.presentationExchange) {
          throw new Error(
            "Missing presentation exchange on resolved authorization request"
          );
        }
    
        const submissionResult =
          await this.credoService.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
            authorizationRequest: resolvedPresentationRequest.authorizationRequest,
            presentationExchange: {
              credentials: presentationExchangeService.selectCredentialsForRequest(
                resolvedPresentationRequest.presentationExchange
                  .credentialsForRequest
              ),
            },
          });
    
        return submissionResult.serverResponse;
      }
    
      public async createOIDProofRequest(
        presentationDefinition: DifPresentationExchangeDefinitionV2,
      ) {
        const agent = this.credoService.agent;
        const { authorizationRequest } =
          await agent.modules.openId4VcVerifier.createAuthorizationRequest({
            requestSigner: {
              method: "did",
              didUrl: this.credoService.verificationMethod.id,
            },
            verifierId: this.credoService.verifierRecord.verifierId,
            presentationExchange: {
              definition: presentationDefinition,
            },
          });
    
        return authorizationRequest;
      }
    
}
