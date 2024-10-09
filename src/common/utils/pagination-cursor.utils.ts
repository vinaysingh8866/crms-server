import { QueryDto } from 'src/connections/dto/connections.dto';

/**
 * Performs cursor-based pagination on an array of items.
 * @param items Array of items to paginate.
 * @param query Pagination parameters.
 * @param idField Field name representing the unique identifier.
 * @returns Paginated result including data, next cursor, previous cursor, and limit.
 */
export function cursorPaginate(items: any[], query?: QueryDto, idField = 'id') {
  const { limit, direction, cursor } = query?.pagination || {
    limit: 50,
    cursor: undefined,
  };
  const parsedLimit = parseInt(limit.toString(), 10);
  let startIndex = 0;
  if (cursor) {
    try {
      startIndex = items.findIndex((item) => item[idField] === cursor);
      if (direction === 'next') {
        startIndex += 1;
      } else if (direction === 'previous') {
        startIndex = Math.max(0, startIndex - parsedLimit);
      }
    } catch (error) {
      throw new Error(`Invalid cursor: ${error.message}`);
    }
  }
  const paginatedItems = items.slice(startIndex, startIndex + parsedLimit);

  if (query?.pagination) {
    query.pagination.cursor =
      paginatedItems[paginatedItems.length - 1][idField];
    query.pagination.direction = 'next';
  }

  const nextCursor =
    paginatedItems.length + startIndex !== items.length
      ? Buffer.from(JSON.stringify(query)).toString('base64')
      : undefined;

  if (query?.pagination) {
    query.pagination.cursor = items[Math.max(0, startIndex)][idField];
    query.pagination.direction = 'previous';
  }

  const previousCursor =
    startIndex > 0
      ? Buffer.from(JSON.stringify(query)).toString('base64')
      : undefined;

  return {
    data: paginatedItems,
    next: nextCursor,
    previous: previousCursor,
    limit: limit,
    lenght: paginatedItems.length,
  };
}
