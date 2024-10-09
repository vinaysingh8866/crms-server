import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { BasicMessageRecord } from '@credo-ts/core';
import { CredoService } from 'src/credo/credo.service';

@Injectable()
export class MessageService {
  private readonly logger = new Logger(MessageService.name);

  constructor(private readonly credoService: CredoService) {}

  /**
   * Retrieve a message by its ID
   *
   * @param messageId - ID of the message to retrieve
   * @returns The message record
   */
  async getMessageById(messageId: string): Promise<BasicMessageRecord> {
    if (!this.credoService.agent) {
      this.logger.error(`[getMessageById] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      this.logger.log(`Retrieving message with ID ${messageId}`);
      const messageRecord =
        await this.credoService.agent.basicMessages.getById(messageId);
      return messageRecord;
    } catch (error) {
      this.logger.error(
        `[getMessageById] Error: Failed to retrieve message with ID ${messageId}.`,
      );
      throw error;
    }
  }

  /**
   * Send a new message to a connection
   *
   * @param connectionId - ID of the connection to send the message to
   * @param message - The message content
   * @returns The sent message record
   */
  async sendMessage(
    connectionId: string,
    message: string,
  ): Promise<BasicMessageRecord> {
    if (!this.credoService.agent) {
      this.logger.error(`[sendMessage] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      this.logger.log(
        `Sending message to connection ID ${connectionId}: ${message}`,
      );
      const [connectionRecord] =
        await this.credoService.agent.connections.findAllByOutOfBandId(
          connectionId,
        );
      if (!connectionRecord) {
        throw new NotFoundException(
          `Connection with ID ${connectionId} not found.`,
        );
      }
      const messageRecord =
        await this.credoService.agent.basicMessages.sendMessage(
          connectionRecord.id,
          message,
        );
      return messageRecord;
    } catch (error) {
      this.logger.error(
        `[sendMessage] Error: Failed to send message.`,
        error.stack,
      );
      throw error;
    }
  }

  /**
   * Delete a message by its ID
   *
   * @param messageId - ID of the message to delete
   * @returns A confirmation message indicating the result of the delete operation
   */
  async deleteMessageById(messageId: string): Promise<string> {
    if (!this.credoService.agent) {
      this.logger.error(`[deleteMessageById] Error: Agent is not initialized.`);
      throw new NotFoundException('Agent is not initialized.');
    }
    try {
      this.logger.log(`Deleting message with ID ${messageId}`);
      await this.credoService.agent.basicMessages.deleteById(messageId);
      return `Message with ID ${messageId} has been deleted successfully.`;
    } catch (error) {
      this.logger.error(
        `[deleteMessageById] Error: Failed to delete message with ID ${messageId}.`,
      );
      throw error;
    }
  }
}
