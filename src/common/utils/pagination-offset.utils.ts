import { OffsetPaginationDto } from './dto/utils.dto';
/**
 * Performs offset-based pagination on an array of items.
 * @param items Array of items to paginate.
 * @param query Pagination parameters.
 * @returns Paginated result including data and total count.
 */
export function offsetPaginate(items: any[], query?: OffsetPaginationDto) {
  const { offset, limit } = query?.pagination || { offset: 0, limit: 50 };

  const startIndex = offset;
  const endIndex = startIndex + limit;

  const paginatedItems = items.slice(startIndex, endIndex);

  return {
    data: paginatedItems,
    total: items.length,
  };
}
