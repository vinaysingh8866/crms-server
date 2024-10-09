import { Test, TestingModule } from '@nestjs/testing';
import { CredoService } from './credo.service';
import { CredoController } from './credo.controller';

describe('CredoService', () => {
  let service: CredoService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CredoController],
      providers: [CredoService],
    }).compile();

    service = module.get<CredoService>(CredoService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
