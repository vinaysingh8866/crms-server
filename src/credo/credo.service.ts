import { Injectable, Logger } from "@nestjs/common";
import {
  Agent,
  HttpOutboundTransport,
  WsOutboundTransport,
  InitConfig,
  OutOfBandRecord,
  ConnectionStateChangedEvent,
  ConnectionEventTypes,
  DidExchangeState,
  ConnectionsModule,
  DidsModule,
  CredentialsModule,
  V2CredentialProtocol,
  CredentialStateChangedEvent,
  CredentialEventTypes,
  CredentialState,
  ConsoleLogger,
  LogLevel,
  DidKey,
  W3cCredential,
  CredoError,
  ClaimFormat,
  W3cIssuer,
  W3cCredentialSubject,
  w3cDate,
  parseDid,
  DidsApi,
  KeyDidCreateOptions,
  KeyType,
  TypedArrayEncoder,
  VerificationMethod,
  W3cJwtVerifiableCredential,
  W3cJsonLdVerifiableCredential,
  DifPresentationExchangeService,
  DifPresentationExchangeDefinitionV2,
} from "@credo-ts/core";
import { HttpInboundTransport, agentDependencies } from "@credo-ts/node";
import { AskarModule } from "@credo-ts/askar";
import { ariesAskar } from "@hyperledger/aries-askar-nodejs";
import {
  IndyVdrAnonCredsRegistry,
  IndyVdrIndyDidRegistrar,
  IndyVdrIndyDidResolver,
  IndyVdrModule,
} from "@credo-ts/indy-vdr";
import { indyVdr } from "@hyperledger/indy-vdr-nodejs";
import ledgers from "../config/ledgers/indy/index";
import { QrcodeService } from "src/qrcode/qrcode.service";
import type { IndyVdrPoolConfig } from "@credo-ts/indy-vdr";
import {
  AnonCredsCredentialFormatService,
  AnonCredsModule,
  LegacyIndyCredentialFormatService,
} from "@credo-ts/anoncreds";
import { anoncreds } from "@hyperledger/anoncreds-nodejs";
import {
  OpenId4VcCredentialHolderBinding,
  OpenId4VcCredentialHolderDidBinding,
  OpenId4VciCredentialFormatProfile,
  OpenId4VciCredentialRequestToCredentialMapper,
  OpenId4VciCredentialSupportedWithId,
  OpenId4VciResolvedCredentialOffer,
  OpenId4VciSignCredential,
  OpenId4VcIssuerModule,
  OpenId4VcIssuerRecord,
  OpenId4VcSiopResolvedAuthorizationRequest,
  OpenId4VcVerifierModule,
  OpenId4VcVerifierRecord,
} from "@credo-ts/openid4vc";
import { Router } from "express";
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

@Injectable()
export class CredoService {
  private readonly logger = new Logger(CredoService.name);
  public agent: Agent;
  private config: InitConfig;
  private agents: Map<string, Agent> = new Map();
  public issuerRecord!: OpenId4VcIssuerRecord;
  public did!: string;
  public didKey!: DidKey;
  public kid!: string;
  public verificationMethod!: VerificationMethod;
  constructor(private readonly qrCodeService: QrcodeService) {}
  public verifierRecord!: OpenId4VcVerifierRecord;

  async createAgent(name: string, endpoint: string, port: number) {
    if (this.agents.has(name)) {
      this.logger.log(`Agent ${name} is already initialized on port ${port}`);
      return this.agents.get(name);
    }

    // Agent configuration
    this.config = {
      label: name,
      walletConfig: {
        id: name,
        key: name,
      },
      endpoints: [`${endpoint}:${port}`],
      logger: new ConsoleLogger(LogLevel.info),
    };
    const router = Router();

    this.agent = new Agent({
      config: this.config,
      dependencies: agentDependencies,
      modules: {
        // Register the indyVdr module on the agent
        indyVdr: new IndyVdrModule({
          indyVdr,
          networks: ledgers as [IndyVdrPoolConfig],
        }),

        // Register the Askar module on the agent
        askar: new AskarModule({
          ariesAskar,
        }),
        connections: new ConnectionsModule({ autoAcceptConnections: true }),

        anoncreds: new AnonCredsModule({
          registries: [new IndyVdrAnonCredsRegistry()],
          anoncreds,
        }),

        dids: new DidsModule({
          registrars: [new IndyVdrIndyDidRegistrar()],
          resolvers: [new IndyVdrIndyDidResolver()],
        }),
        openId4VcVerifier: new OpenId4VcVerifierModule({
          baseUrl: "http://localhost:4000/siop",
          router: router,
        }),
        openId4VcIssuer: new OpenId4VcIssuerModule({
          baseUrl: "http://localhost:2000/oid4vci",
          router: router,

          endpoints: {
            credential: {
              credentialRequestToCredentialMapper: async ({
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
              }): Promise<OpenId4VciSignCredential> => {
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
              },
            },
          },
        }),

        // to issue a credential
        credentials: new CredentialsModule({
          credentialProtocols: [
            new V2CredentialProtocol({
              credentialFormats: [
                new LegacyIndyCredentialFormatService(),
                new AnonCredsCredentialFormatService(),
              ],
            }),
          ],
        }),
      },
    });

    // Register a simple `WebSocket` outbound transport
    this.agent.registerOutboundTransport(new WsOutboundTransport());
    // Register a simple `Http` outbound transport
    this.agent.registerOutboundTransport(new HttpOutboundTransport());
    // Register a simple `Http` inbound transport
    this.agent.registerInboundTransport(
      new HttpInboundTransport({ port: port })
    );

    // Initialize the agent
    try {
      await this.agent.initialize();
      await this.agent.modules.openId4VcIssuer.createIssuer({
        credentialsSupported,
      })
      const didCreateResult = await this.agent.dids.create<KeyDidCreateOptions>(
        {
          method: "key",
          options: { keyType: KeyType.Ed25519 },
          secret: {
            privateKey: TypedArrayEncoder.fromString(
              "96213c3d7fc8d4d6754c7a0fd969598g"
            ),
          },
        }
      );
      console.log(didCreateResult, "didCreateResultdidCreateResult");
      this.did = didCreateResult.didState.did as string;
      console.log(this.did, "this.didthis.didthis.did");
      if (this.did) {
        this.didKey = DidKey.fromDid(this.did);
      } else {
        this.didKey = DidKey.fromDid(
          "did:key:z6MktiQQEqm2yapXBDt1WEVB3dqgvyzi96FuFANYmrgTrKV9"
        );
      }

      this.kid = `${this.did}#${this.didKey.key.fingerprint}`;

      const verificationMethod =
        didCreateResult.didState.didDocument?.dereferenceKey(this.kid, [
          "authentication",
        ]);
      console.log(verificationMethod, "verificationMethodverificationMethod");
      if (!verificationMethod) {
        //         VerificationMethod {

        // }
        this.verificationMethod = new VerificationMethod({
          id: "did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ#z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ",
          type: "Ed25519VerificationKey2018",
          controller:
            "did:key:z6MkrzQPBr4pyqC776KKtrz13SchM5ePPbssuPuQZb5t4uKQ",
          publicKeyBase58: "DY9LbbpPeHhdzbUdDJ2ACM4hXWNXyidXDNzUjK7s9gY2",
          publicKeyBase64: undefined,
          publicKeyJwk: undefined,
          publicKeyHex: undefined,
          publicKeyMultibase: undefined,
          publicKeyPem: undefined,
          blockchainAccountId: undefined,
          ethereumAddress: undefined,
        });
      } else {
        this.verificationMethod = verificationMethod;
      }
      // this.verificationMethod = verificationMethod;
      this.agents.set(name, this.agent);
      this.logger.log(
        `Agent ${name} initialized on endpoint ${endpoint}:${port}`
      );
    } catch (e) {
      this.logger.error(
        `Something went wrong while setting up the agent! Message: ${e}`
      );
      throw e;
    }
    return this.agent;
  }

  public async createOID4VCCredentialOffer(
    agentName: string,
    offeredCredentials: string[]
  ) {
    const agent: Agent | undefined = this.agent;
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }
    console.log(this.issuerRecord)
    const { credentialOffer } =
      await agent.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: this.issuerRecord.issuerId,
        offeredCredentials,
        preAuthorizedCodeFlowConfig: { userPinRequired: false },
      });

    return credentialOffer;
  }

  public async resolveCredentialOffer(
    credentialOffer: string,
    agentName: string
  ) {
    const agent = this.getAgentByName(agentName);
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }
    return await agent.modules.openId4VcHolder.resolveCredentialOffer(
      credentialOffer
    );
  }

  public async resolveProofRequest(proofRequest: string, agentName: string) {
    const agent = this.getAgentByName(agentName);
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }
    const resolvedProofRequest =
      await agent.modules.openId4VcHolder.resolveSiopAuthorizationRequest(
        proofRequest
      );

    return resolvedProofRequest;
  }
  public async acceptPresentationRequest(
    resolvedPresentationRequest: OpenId4VcSiopResolvedAuthorizationRequest,
    agentName: string
  ) {
    const agent = this.getAgentByName(agentName);
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }
    const presentationExchangeService = agent.dependencyManager.resolve(
      DifPresentationExchangeService
    );

    if (!resolvedPresentationRequest.presentationExchange) {
      throw new Error(
        "Missing presentation exchange on resolved authorization request"
      );
    }

    const submissionResult =
      await this.agent.modules.openId4VcHolder.acceptSiopAuthorizationRequest({
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

  public async createProofRequest(
    presentationDefinition: DifPresentationExchangeDefinitionV2,
    agentName: string
  ) {
    const agent = this.getAgentByName(agentName);
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }
    const { authorizationRequest } =
      await agent.modules.openId4VcVerifier.createAuthorizationRequest({
        requestSigner: {
          method: "did",
          didUrl: this.verificationMethod.id,
        },
        verifierId: this.verifierRecord.verifierId,
        presentationExchange: {
          definition: presentationDefinition,
        },
      });

    return authorizationRequest;
  }

  // This method will create an invitation using the legacy method according to 0160: Connection Protocol.
  async createLegacyInvitation(agentName: string) {
    const agent: Agent | undefined = this.getAgentByName(agentName);
    if (agent) {
      this.logger.log(`Creating legacy invitation for agent: ${agentName}`);
      try {
        // Creating a Legacy Invitation
        const { invitation } = await agent.oob.createLegacyInvitation();
        const invitationUrl = invitation.toUrl({
          domain: agent.config?.endpoints[0] ?? "https://example.org",
        });
        this.logger.log(`Legacy Invitation link created: ${invitationUrl}`);
        return { invitationUrl };
      } catch (error) {
        this.logger.error(`Error creating legacy invitation: ${error}`);
        throw error;
      }
    } else {
      this.logger.error(`Agent ${agentName} not found`);
    }
  }

  // This method will create an invitation using the legacy method according to 0434: Out-of-Band Protocol 1.1.
  async createNewInvitation(agentName: string) {
    const agent: Agent | undefined = this.getAgentByName(agentName);
    if (agent) {
      this.logger.log(`Creating new invitation for agent: ${agentName}`);
      try {
        const outOfBandRecord = await agent.oob.createInvitation();
        const invitationUrl = outOfBandRecord.outOfBandInvitation.toUrl({
          domain: agent.config?.endpoints[0] ?? "https://example.org",
        });
        const invitationUrlQRcode =
          await this.qrCodeService.generateQrCode(invitationUrl);
        this.logger.log(`New Invitation link created: ${invitationUrl}`);
        // Listener
        this.setupConnectionListener(agent, outOfBandRecord, () => {});
        return {
          invitationUrlQRcode,
        };
      } catch (error) {
        this.logger.error(`Error creating new invitation: ${error}`);
        throw error;
      }
    } else {
      this.logger.error(`Agent ${agentName} not found`);
    }
  }

  public async createCredentialOffer(offeredCredentials: string[]) {
    const { credentialOffer } =
      await this.agent.modules.openId4VcIssuer.createCredentialOffer({
        issuerId: this.issuerRecord.issuerId,
        offeredCredentials,
        preAuthorizedCodeFlowConfig: { userPinRequired: false },
      });

    return credentialOffer;
  }

  async receiveInvitation(agentName: string, invitationUrl: string) {
    const agent: Agent | undefined = this.getAgentByName(agentName);
    if (agent) {
      try {
        const { outOfBandRecord } =
          await agent.oob.receiveInvitationFromUrl(invitationUrl);
        this.logger.log(`Received invitation for agent ${agentName}`);
        this.logger.log(
          `OutOfBandRecord received: ${JSON.stringify(outOfBandRecord)}`
        );
      } catch (error) {
        this.logger.error(
          `Error receiving invitation for agent ${agentName}: ${error}`
        );
        throw error;
      }
    } else {
      this.logger.error(`Agent ${agentName} not found`);
    }
  }

  setupConnectionListener(
    agent: Agent,
    outOfBandRecord: OutOfBandRecord,
    cb: (...args: any) => void
  ) {
    agent.events.on<ConnectionStateChangedEvent>(
      ConnectionEventTypes.ConnectionStateChanged,
      ({ payload }) => {
        if (payload.connectionRecord.outOfBandId !== outOfBandRecord.id) return;
        if (payload.connectionRecord.state === DidExchangeState.Completed) {
          // the connection is now ready for usage in other protocols!
          this.logger.log(
            `Connection for out-of-band id ${outOfBandRecord.id} completed.`
          );

          // Custom business logic can be included here
          // In this example we can send a basic message to the connection, but
          // anything is possible
          cb();

          // Set up credential listener
          console.log("setupCredentialListener");
          this.setupCredentialListener(agent);

          // We exit the flow
          // process.exit(0);
        }
      }
    );
  }

  getAgentByName(name: string) {
    return this.agents.get(name);
  }

  getOutOfBandRecordById(id: string): Promise<OutOfBandRecord | null> {
    return this.agent.oob.findById(id);
  }

  async issueCredential(
    connectionId: string,
    credentialDefinitionId: string,
    attributes: any
  ) {
    const [connectionRecord] =
      await this.agent.connections.findAllByOutOfBandId(connectionId);

    if (!connectionRecord) {
      throw new Error(
        `ConnectionRecord: record with id ${connectionId} not found.`
      );
    }

    console.log(attributes, "attributesattributesattributes");
    const credentialExchangeRecord =
      await this.agent.credentials.offerCredential({
        connectionId: connectionRecord.id,
        credentialFormats: {
          anoncreds: {
            credentialDefinitionId,
            attributes,
          },
        },
        protocolVersion: "v2" as never,
      });

    return credentialExchangeRecord;
  }

  setupCredentialListener(agent: Agent) {
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
}
