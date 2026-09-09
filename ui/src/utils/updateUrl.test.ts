import {
  UpdateURL,
  readAuthCallbackParams,
  strippedAuthCallbackLocation
} from './updateUrl';

describe('Test UpdateUrl function', () => {
  it('Test UpdateUrl function', () => {
    const val = UpdateURL('', 'rating', 'cli', 'task', 'Tekton', 'linux/amd64', ['cli', 'gke']);
    expect(val).toEqual(
      'sortBy=rating&category=cli&platform=linux%2Famd64&kind=task&catalog=Tekton&tag=cli&tag=gke'
    );
  });

  it('clears oauth callback params including provider', () => {
    const location = window.location;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { search: '?code=abc&status=200&provider=github&sortBy=rating' }
    });

    const val = UpdateURL('', 'rating', '', '', '', '', []);
    expect(val).toEqual('sortBy=rating');

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: location
    });
  });

  it('clears oauth callback params from the hash', () => {
    window.history.replaceState({}, '', '/?sortBy=rating#code=abc&status=200&provider=github');

    const val = UpdateURL('', 'rating', '', '', '', '', []);
    expect(val).toEqual('sortBy=rating');
    expect(window.location.hash).toBe('');
    expect(window.location.search).not.toContain('code=');

    window.history.replaceState({}, '', '/');
  });
});

describe('auth callback location helpers', () => {
  it('prefers hash params over the query string', () => {
    const params = readAuthCallbackParams(
      '?status=200&code=query-code&provider=bitbucket',
      '#status=200&code=hash-code&provider=github'
    );
    expect(params.get('code')).toBe('hash-code');
    expect(params.get('provider')).toBe('github');
  });

  it('falls back to query-string params', () => {
    const params = readAuthCallbackParams('?status=200&code=query-code&provider=github', '');
    expect(params.get('code')).toBe('query-code');
    expect(params.get('status')).toBe('200');
  });

  it('strips oauth params from hash and query', () => {
    expect(
      strippedAuthCallbackLocation(
        '/',
        '?query=ansible&code=abc&status=200&provider=github',
        '#status=200&code=abc&provider=github'
      )
    ).toBe('/?query=ansible');
  });
});
