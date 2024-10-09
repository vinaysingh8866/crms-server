export class FilterDto {
  state?: string;
  theirLabel?: string;
  role?: string;
  id?: string;
  did?: string;
  threadId?: string;
  metadata?: { key: string; value: string };
}

export class SortDto {
  attribute:
    | 'state'
    | 'role'
    | 'id'
    | 'did'
    | 'createdAt'
    | 'updatedAt'
    | 'metadata_value';
  order: 'asc' | 'desc';
}

export class PaginationDto {
  direction?: 'next' | 'previous';
  limit: number;
  cursor?: string;
}

export class QueryDto {
  filter?: FilterDto;
  sort?: SortDto;
  pagination?: PaginationDto;
}
