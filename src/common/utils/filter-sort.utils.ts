import { FilterDto, SortDto } from 'src/connections/dto/connections.dto';

/**
 * Applies filtering to an array of items based on the provided filter criteria.
 * @param items Array of items to filter.
 * @param filter Filter criteria to apply.
 * @returns The filtered array of items.
 */
export function applyFilter(items: any[], filter?: FilterDto) {
  if (!filter) return items;
  return items.filter((item) => {
    for (const key in filter) {
      if (key === 'metadata') {
        const { key: metaKey, value: metaValue } = filter.metadata!;
        if (!item.metadata[metaKey] || item.metadata[metaKey] !== metaValue) {
          return false;
        }
      } else if (item[key] !== (filter as any)[key]) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Applies sorting to an array of items based on the provided sort criteria.
 * @param items Array of items to sort.
 * @param sort Sort criteria to apply.
 * @returns The sorted array of items.
 */
export function applySort(items: any[], sort: SortDto) {
  return items.sort((a, b) => {
    const valueA = a[sort.attribute];
    const valueB = b[sort.attribute];
    if (valueA < valueB) {
      return sort.order === 'asc' ? -1 : 1;
    } else if (valueA > valueB) {
      return sort.order === 'asc' ? 1 : -1;
    } else {
      return 0;
    }
  });
}
