import { Test, TestingModule } from '@nestjs/testing';
import { Oid4vcService } from './oid4vc.service';

describe('Oid4vcService', () => {
  let service: Oid4vcService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [Oid4vcService],
    }).compile();

    service = module.get<Oid4vcService>(Oid4vcService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
