import { Injectable, Logger } from '@nestjs/common';
import { QueryDto } from './dto/connections.dto';
import { CredoService } from 'src/credo/credo.service';
import { ConnectionRecord, ConnectionType } from '@credo-ts/core';
import { applyFilter, applySort } from 'src/common/utils/filter-sort.utils';
import { cursorPaginate } from 'src/common/utils/pagination-cursor.utils';

@Injectable()
export class ConnectionsService {
  private readonly logger = new Logger(ConnectionsService.name);
  // Define a constant for the dynamic identifier
  private readonly idField = 'id';

  constructor(private readonly credoService: CredoService) {}

  /**
   * Retrieve all connections with optional filtering, sorting, and pagination.
   * @param query Query parameters for filtering, sorting, and pagination.
   * @returns A promise resolving to the filtered, sorted, and paginated connections.
   */
  async findAll(query: QueryDto): Promise<any> {
    try {
      this.logger.log('Retrieving all connections');
      const connections: any =
        await this.credoService.agent.connections.getAll();

      // Apply filtering
      let filteredConnections = applyFilter(connections, query?.filter);

      // Apply sorting
      if (query.sort) {
        filteredConnections = applySort(filteredConnections, query.sort);
      }

      // Apply cursor pagination
      // const paginatedResult = cursorPaginate(
      //   filteredConnections,
      //   query,
      //   this.idField,
      // );

      return filteredConnections;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections.`);
      throw error;
    }
  }

  /**
   * Find a connection by its ID.
   * @param id The ID of the connection to find.
   * @returns A promise resolving to the found connection.
   */
  async findById(id: string): Promise<any> {
    try {
      this.logger.log(`Retrieving connection by ID: ${id}`);
      const connection = await this.credoService.agent.connections.findById(id);
      if (!connection) {
        this.logger.warn(`Connection with ID ${id} not found`);
      }
      return connection;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by ID`);
      throw error;
    }
  }

  /**
   * Find a connection by its DID.
   * @param did The DID of the connection to find.
   * @returns A promise resolving to the found connection record.
   */
  async findByDid(did: string): Promise<ConnectionRecord | null> {
    try {
      /* Note: It's based on theirDid value */
      this.logger.log(`Retrieving connection by DID: ${did}`);
      const connection =
        await this.credoService.agent.connections.findByDid(did);
      if (!connection) {
        this.logger.warn(`Connection with DID ${did} not found`);
      }
      return connection;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by DID`);
      throw error;
    }
  }

  /**
   * Find a connection by its thread ID.
   * @param threadId The thread ID of the connection to find.
   * @returns A promise resolving to the found connection record.
   */
  async getByThreadId(threadId: string): Promise<ConnectionRecord> {
    try {
      this.logger.log(`Retrieving connection by thread ID: ${threadId}`);
      const connection =
        await this.credoService.agent.connections.getByThreadId(threadId);
      if (!connection) {
        this.logger.warn(`Connection with thread ID ${threadId} not found`);
      }
      return connection;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by thread ID`);
      throw error;
    }
  }

  /**
   * Find connections by invitation DID.
   * @param invitationDid The invitation DID to search connections by.
   * @returns A promise resolving to an array of connection records.
   */
  async findByInvitationDid(
    invitationDid: string,
  ): Promise<ConnectionRecord[]> {
    try {
      this.logger.log(
        `Retrieving connections by invitation DID: ${invitationDid}`,
      );
      const connections =
        await this.credoService.agent.connections.findByInvitationDid(
          invitationDid,
        );
      if (!connections.length) {
        this.logger.warn(
          `Connections with invitation DID ${invitationDid} not found`,
        );
      }
      return connections;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by invitation DID`);
      throw error;
    }
  }

  /**
   * Find all connections by out-of-band ID.
   * @param outOfBandId The out-of-band ID to search connections by.
   * @returns A promise resolving to an array of connection records.
   */
  async findAllByOutOfBandId(outOfBandId: string): Promise<ConnectionRecord[]> {
    try {
      this.logger.log(
        `Retrieving connections by out of band ID: ${outOfBandId}`,
      );
      const connections =
        await this.credoService.agent.connections.findAllByOutOfBandId(
          outOfBandId,
        );
      if (!connections.length) {
        this.logger.warn(
          `Connections with out of band ID ${outOfBandId} not found`,
        );
      }
      return connections;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by out of band ID`);
      throw error;
    }
  }

  /**
   * Find all connections by connection types.
   * @param connectionTypes An array of connection types to search connections by.
   * @returns A promise resolving to an array of connection records.
   */
  async findAllByConnectionTypes(
    connectionTypes: Array<ConnectionType | string>,
  ): Promise<ConnectionRecord[]> {
    try {
      this.logger.log(
        `Retrieving connections by connection types: ${connectionTypes}`,
      );
      const connections =
        await this.credoService.agent.connections.findAllByConnectionTypes(
          connectionTypes,
        );
      if (!connections.length) {
        this.logger.warn(
          `Connections with connection types ${connectionTypes} not found`,
        );
      }
      return connections;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by connection types`);
      throw error;
    }
  }

  /**
   * Delete a connection by its ID.
   * @param connectionId The ID of the connection to delete.
   * @returns A promise resolving after the deletion.
   */
  async deleteById(connectionId: string): Promise<void> {
    try {
      this.logger.log(`Deleting connection by ID: ${connectionId}`);
      await this.credoService.agent.connections.deleteById(connectionId);
      this.logger.log(
        `Connection with ID ${connectionId} deleted successfully`,
      );
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by ID`);
      throw error;
    }
  }

  /**
   * Find connections by query parameters.
   * @param query The query parameters to search connections by.
   * @returns A promise resolving to an array of connection records.
   */
  async findAllByQuery(query: any): Promise<ConnectionRecord[]> {
    try {
      this.logger.log(
        `Retrieving connections by query: ${JSON.stringify(query)}`,
      );
      const connections =
        await this.credoService.agent.connections.findAllByQuery(query);
      if (!connections.length) {
        this.logger.warn(
          `Connections matching query ${JSON.stringify(query)} not found`,
        );
      }
      return connections;
    } catch (error) {
      this.logger.error(`Failed to retrieve connections by query`);
      throw error;
    }
  }
}
