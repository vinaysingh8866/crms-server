import { Controller, Post, Body, Param, Get, Delete } from '@nestjs/common';
import { BasicMessageRecord } from '@credo-ts/core';
import { MessageService } from './message.service';
import { SendMessageDto } from './dto/message.dto';
import {
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { API_VERSION } from 'src/constants';

@ApiTags('Message')
@Controller(`${API_VERSION}/message`)
export class MessageController {
  constructor(private readonly messageService: MessageService) {}

  /**
   * Retrieve a message by its ID
   *
   * @param messageId - ID of the message to retrieve
   * @returns The message record
   */
  @Get(':id')
  @ApiOperation({ summary: 'Retrieve a message by its ID' })
  @ApiParam({ name: 'id', description: 'ID of the message to retrieve' })
  @ApiResponse({
    status: 200,
    description: 'The message record',
    type: BasicMessageRecord,
  })
  @ApiResponse({ status: 404, description: 'Message not found' })
  async getMessageById(
    @Param('id') messageId: string,
  ): Promise<{ message: BasicMessageRecord }> {
    const messageRecord = await this.messageService.getMessageById(messageId);
    return { message: messageRecord };
  }

  /**
   * Send a new message
   *
   * @param sendMessageDto - Data transfer object containing connectionId and message content
   * @returns The sent message record
   */
  @Post('send')
  @ApiOperation({ summary: 'Send a new message' })
  @ApiBody({ type: SendMessageDto })
  @ApiResponse({
    status: 201,
    description: 'The sent message record',
    type: BasicMessageRecord,
  })
  async sendMessage(
    @Body() sendMessageDto: SendMessageDto,
  ): Promise<{ message: BasicMessageRecord }> {
    const message = await this.messageService.sendMessage(
      sendMessageDto.connectionId,
      sendMessageDto.message,
    );
    return { message };
  }

  /**
   * Delete a message by its ID
   *
   * @param messageId - ID of the message to delete
   * @returns Confirmation message indicating the result of the delete operation
   */
  @Delete(':id')
  @ApiOperation({ summary: 'Delete a message by its ID' })
  @ApiParam({ name: 'id', description: 'ID of the message to delete' })
  @ApiResponse({
    status: 200,
    description: 'Confirmation message',
    type: String,
  })
  @ApiResponse({ status: 404, description: 'Message not found' })
  async deleteMessageById(
    @Param('id') messageId: string,
  ): Promise<{ message: string }> {
    const confirmationMessage =
      await this.messageService.deleteMessageById(messageId);
    return { message: confirmationMessage };
  }
}
