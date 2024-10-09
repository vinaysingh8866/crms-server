import { Test, TestingModule } from '@nestjs/testing';
import { CredoController } from './credo.controller';

describe('CredoController', () => {
  let controller: CredoController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CredoController],
    }).compile();

    controller = module.get<CredoController>(CredoController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
