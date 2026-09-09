import { Params } from '../common/params';
import { SortByFields } from '../store/resource';
import { titleCase } from '../common/titlecase';

export const AUTH_CALLBACK_PARAMS = [Params.Code, Params.Status, Params.Provider];

const hashSearchParams = (hash: string): URLSearchParams => {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash;
  return new URLSearchParams(raw);
};

export const readAuthCallbackParams = (search: string, hash: string): URLSearchParams => {
  const hashParams = hashSearchParams(hash || '');
  if (AUTH_CALLBACK_PARAMS.some((key) => hashParams.has(key))) {
    return hashParams;
  }
  return new URLSearchParams(search || '');
};

export const strippedAuthCallbackLocation = (
  pathname: string,
  search: string,
  hash: string
): string => {
  const searchParams = new URLSearchParams(search || '');
  const hashParams = hashSearchParams(hash || '');
  AUTH_CALLBACK_PARAMS.forEach((key) => {
    searchParams.delete(key);
    hashParams.delete(key);
  });
  const nextSearch = searchParams.toString();
  const nextHash = hashParams.toString();
  return `${pathname}${nextSearch ? `?${nextSearch}` : ''}${nextHash ? `#${nextHash}` : ''}`;
};

// This function returns all selected filters in a combination of params
export const UpdateURL = (
  search: string,
  sort: string,
  categories: string,
  kinds: string,
  catalogs: string,
  platforms: string,
  tags: Array<string>
) => {
  // To get URLSearchParams object instance
  const searchParams = new URLSearchParams(window.location.search);

  // To delete query params if search is empty
  if (!search && searchParams.has(Params.Query)) searchParams.delete(Params.Query);

  // Sets query params
  if (search) searchParams.set(Params.Query, search);

  //To delete sort params if doesn't selected any sort
  if (sort === SortByFields.Unknown && searchParams.has(Params.SortBy))
    searchParams.delete(Params.SortBy);

  // Set sort params
  if (sort !== SortByFields.Unknown) searchParams.set(Params.SortBy, sort);

  // To delete category params if doesn't selected any category
  if (!categories && searchParams.has(Params.Category)) searchParams.delete(Params.Category);

  // Sets category params
  if (categories) searchParams.set(Params.Category, categories);

  // To delete platform params if doesn't selected any platform
  if (!platforms && searchParams.has(Params.Platform)) searchParams.delete(Params.Platform);

  // Sets platform params
  if (platforms) searchParams.set(Params.Platform, platforms);

  // To delete kind params if doesn't selected any kind
  if (!kinds && searchParams.has(Params.Kind)) searchParams.delete(Params.Kind);

  // Sets Kind params
  if (kinds) searchParams.set(Params.Kind, kinds);

  // To delete catalog params if doesn't selected any catalog
  if (!catalogs && searchParams.has(Params.Catalog)) searchParams.delete(Params.Catalog);

  // Sets catalos params
  if (catalogs) searchParams.set(Params.Catalog, titleCase(catalogs));

  // To delete tag param
  if (tags.length === 0) searchParams.delete(Params.Tag);

  // Sets tag params
  if (tags.length > 0) {
    searchParams.delete(Params.Query);
    searchParams.delete(Params.Tag);
    tags.forEach((t: string) => {
      searchParams.append(Params.Tag, t);
    });
  }

  // After redirection needs to delete Code & Status from query and hash
  AUTH_CALLBACK_PARAMS.forEach((key) => searchParams.delete(key));

  const hash = window.location.hash || '';
  const hashParams = hashSearchParams(hash);
  if (
    AUTH_CALLBACK_PARAMS.some((key) => hashParams.has(key)) &&
    typeof window.history.replaceState === 'function' &&
    window.location.pathname
  ) {
    window.history.replaceState(
      window.history.state,
      '',
      strippedAuthCallbackLocation(window.location.pathname, window.location.search || '', hash)
    );
  }

  return searchParams.toString();
};
