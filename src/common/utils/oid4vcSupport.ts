import { Agent, ClaimFormat, CredentialEventTypes, CredentialState, CredentialStateChangedEvent, CredoError, DidKey, DidsApi, parseDid, W3cCredential, W3cCredentialSubject, w3cDate, W3cIssuer } from "@credo-ts/core";
import { OpenId4VcCredentialHolderBinding, OpenId4VcCredentialHolderDidBinding, OpenId4VciCredentialFormatProfile, OpenId4VciCredentialSupportedWithId, OpenId4VciSignCredential } from "@credo-ts/openid4vc";
export const universityDegreeCredential = {
    id: "UniversityDegreeCredential",
    format: OpenId4VciCredentialFormatProfile.JwtVcJson,
    types: ["VerifiableCredential", "UniversityDegreeCredential"],
  } satisfies OpenId4VciCredentialSupportedWithId;
  
  export const openBadgeCredential = {
    id: "OpenBadgeCredential",
    format: OpenId4VciCredentialFormatProfile.JwtVcJson,
    types: ["VerifiableCredential", "OpenBadgeCredential"],
  } satisfies OpenId4VciCredentialSupportedWithId;
  
  export const universityDegreeCredentialSdJwt = {
    id: "UniversityDegreeCredential-sdjwt",
    format: OpenId4VciCredentialFormatProfile.SdJwtVc,
    vct: "UniversityDegreeCredential",
  } satisfies OpenId4VciCredentialSupportedWithId;
  
  export const credentialsSupported = [
    universityDegreeCredential,
    openBadgeCredential,
    universityDegreeCredentialSdJwt,
  ] satisfies OpenId4VciCredentialSupportedWithId[];
  function assertDidBasedHolderBinding(
    holderBinding: OpenId4VcCredentialHolderBinding
  ): asserts holderBinding is OpenId4VcCredentialHolderDidBinding {
    if (holderBinding.method !== "did") {
      throw new CredoError(
        "Only did based holder bindings supported for this credential type"
      );
    }
  }
export async function credentialRequestToCredentialMapper ({
    // agent context for the current wallet / tenant
    agentContext,
    // the credential offer related to the credential request
    credentialOffer,
    // the received credential request
    credentialRequest,
    // the list of credentialsSupported entries
    credentialsSupported,
    // the cryptographic binding provided by the holder in the credential request proof
    holderBinding,
    // the issuance session associated with the credential request and offer
    issuanceSession,
    credentialConfigurationIds,
  }:{
    //@todo: add types
    agentContext: any,
    credentialOffer: any,
    credentialRequest: any,
    credentialsSupported: any,
    holderBinding: any,
    issuanceSession: any,
    credentialConfigurationIds: any
  }): Promise<OpenId4VciSignCredential> {
    // find the first did:key did in our wallet. You can modify this based on your needs
    const didsApi = agentContext.dependencyManager.resolve(DidsApi);
    const [didKeyDidRecord] = await didsApi.getCreatedDids({
      method: "key",
    });
    if (!didKeyDidRecord) {
      throw new Error("No did:key did found in wallet");
    }

    const didKey = DidKey.fromDid(didKeyDidRecord.did);
    const didUrl = `${didKey.did}#${didKey.key.fingerprint}`;
    const issuerDidKey = didKey;
    const credentialConfigurationId = credentialConfigurationIds[0];
    if (
      credentialConfigurationId === universityDegreeCredential.id
    ) {
      assertDidBasedHolderBinding(holderBinding);

      return {
        credentialSupportedId: universityDegreeCredential.id,
        format: ClaimFormat.JwtVc,
        credential: new W3cCredential({
          type: universityDegreeCredential.types,
          issuer: new W3cIssuer({
            id: issuerDidKey.did,
          }),
          credentialSubject: new W3cCredentialSubject({
            id: parseDid(holderBinding.didUrl).did,
          }),
          issuanceDate: w3cDate(Date.now()),
        }),
        verificationMethod: `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`,
      };
    }

    if (credentialConfigurationId === openBadgeCredential.id) {
      assertDidBasedHolderBinding(holderBinding);

      return {
        format: ClaimFormat.JwtVc,
        credentialSupportedId: openBadgeCredential.id,
        credential: new W3cCredential({
          type: openBadgeCredential.types,
          issuer: new W3cIssuer({
            id: issuerDidKey.did,
          }),
          credentialSubject: new W3cCredentialSubject({
            id: parseDid(holderBinding.didUrl).did,
          }),
          issuanceDate: w3cDate(Date.now()),
        }),
        verificationMethod: `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`,
      };
    }

    if (
      credentialConfigurationId ===
      universityDegreeCredentialSdJwt.id
    ) {
      return {
        credentialSupportedId: universityDegreeCredentialSdJwt.id,
        format: ClaimFormat.SdJwtVc,
        payload: {
          vct: universityDegreeCredentialSdJwt.vct,
          university: "innsbruck",
          degree: "bachelor",
        },
        holder: holderBinding,
        issuer: {
          method: "did",
          didUrl: `${issuerDidKey.did}#${issuerDidKey.key.fingerprint}`,
        },
        disclosureFrame: { _sd: ["university", "degree"] },
      };
    }

    throw new Error("Invalid request");
  }

export function setupCredentialListener(agent: Agent) {
    agent.events.on<CredentialStateChangedEvent>(
      CredentialEventTypes.CredentialStateChanged,
      async ({ payload }) => {
        this.logger.log(
          `Credential state changed: ${payload.credentialRecord.id}, state: ${payload.credentialRecord.state}`
        );

        switch (payload.credentialRecord.state) {
          case CredentialState.OfferSent:
            this.logger.log(`Credential offer sent to holder.`);
            break;
          case CredentialState.RequestReceived:
            this.logger.log(`Credential request received from holder.`);
            // Automatically respond to credential request if desired
            await this.agent.credentials.acceptRequest({
              credentialRecordId: payload.credentialRecord.id,
            });
            break;
          case CredentialState.CredentialIssued: // Adjusted to match your enum
            this.logger.log(`Credential issued to holder.`);
            // Handle the issuance process or update state as necessary
            break;
          case CredentialState.Done:
            this.logger.log(
              `Credential ${payload.credentialRecord.id} is accepted by the wallet`
            );
            // Add your custom business logic here, e.g., updating your database or notifying a service
            break;
          case CredentialState.Declined:
            this.logger.log(
              `Credential ${payload.credentialRecord.id} is rejected by the wallet`
            );
            // Handle rejection if needed
            break;
          default:
            this.logger.log(
              `Unhandled credential state: ${payload.credentialRecord.state}`
            );
        }
      }
    );
  }