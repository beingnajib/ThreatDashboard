import { useState } from "react";

import { useApi, useDebounced } from "./useApi";

/** Paged, searchable, sortable list backed by a DRF endpoint. */
export function useList(path, { initialFilters = {}, ordering: initialOrdering = "", pollMs = 0, pageSize = 25 } = {}) {
  const [page, setPage] = useState(1);
  const [search, setSearchRaw] = useState("");
  const [filters, setFiltersRaw] = useState(initialFilters);
  const [ordering, setOrderingRaw] = useState(initialOrdering);
  const debounced = useDebounced(search);
  const params = { page, page_size: pageSize, search: debounced, ordering, ...filters };
  const result = useApi(path, params, { pollMs });

  return {
    ...result,
    rows: result.data?.results,
    count: result.data?.count || 0,
    page,
    pageSize,
    setPage,
    search,
    setSearch: (value) => { setSearchRaw(value); setPage(1); },
    filters,
    setFilter: (key, value) => { setFiltersRaw((f) => ({ ...f, [key]: value })); setPage(1); },
    ordering,
    setOrdering: (value) => { setOrderingRaw(value); setPage(1); },
  };
}
