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
  ConsoleLogger,
  LogLevel,
  DidKey,
  KeyDidCreateOptions,
  KeyType,
  TypedArrayEncoder,
  VerificationMethod,
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
  OpenId4VcIssuerModule,
  OpenId4VcIssuerRecord,
  OpenId4VcVerifierModule,
  OpenId4VcVerifierRecord,
} from "@credo-ts/openid4vc";
import express from "express";
import { Router } from "express";
import {
  credentialRequestToCredentialMapper,
  credentialsSupported,
  setupCredentialListener,
} from "src/common/utils/oid4vcSupport";

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
  private app: any;
  async createAgent(
    name: string,
    endpoint: string,
    port: number,
    oid4vcPort: number
  ) {
    if (this.agents.has(name)) {
      this.logger.log(`Agent ${name} is already initialized on port ${port}`);
      return this.agents.get(name);
    }
    this.app = express();

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
    const verifierRouter = Router();
    const issuerRouter = Router();
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
          baseUrl: `http://${endpoint}:${oid4vcPort}/siop`, //"http://localhost:2000/siop",
          router: verifierRouter,
        }),
        openId4VcIssuer: new OpenId4VcIssuerModule({
          baseUrl: `http://${endpoint}:${oid4vcPort}/oid4vci`,
          router: issuerRouter,

          endpoints: {
            credential: {
              credentialRequestToCredentialMapper:
                credentialRequestToCredentialMapper,
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
    this.app.use("/siop", verifierRouter);
    this.app.use("/oid4vci", issuerRouter);
    this.app.listen(2000, () => {
      console.log("Oidc Server listening on port 3000");
    });

    // Initialize the agent
    try {
      await this.agent.initialize();
      this.issuerRecord = await this.agent.modules.openId4VcIssuer.createIssuer(
        {
          credentialsSupported,
        }
      );

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
        this.logger.log("No DID found, using default");
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
        this.logger.log("No verification method found, using default");
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
          setupCredentialListener(agent);

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
}
