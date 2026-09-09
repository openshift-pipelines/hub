import React from 'react';
import { mount } from 'enzyme';
import { when } from 'mobx';
import { BrowserRouter as Router } from 'react-router-dom';
import { FakeHub } from '../../api/testutil';
import { createProviderAndStore } from '../../store/root';
import ParseUrl from '.';

const TESTDATA_DIR = `src/store/testdata`;
const api = new FakeHub(TESTDATA_DIR);
const { Provider, root } = createProviderAndStore(api);

describe('ParseUrl component', () => {
  afterEach(() => {
    window.history.replaceState({}, '', '/');
  });

  it('it can set url params to resource store', (done) => {
    const { resources } = root;
    when(
      () => {
        return !resources.isLoading;
      },
      () => {
        resources.setURLParams('?/query=ansible');
        expect(resources.urlParams).toBe('?/query=ansible');

        done();
      }
    );
  });

  it('reads oauth params from the hash and strips them from the address bar', () => {
    window.history.replaceState({}, '', '/#status=200&code=foo&provider=github');
    const spy = jest.spyOn(root.user, 'authenticate');

    mount(
      <Provider>
        <Router>
          <ParseUrl />
        </Router>
      </Provider>
    );

    expect(spy).toHaveBeenCalledWith({ code: 'foo', provider: 'github' });
    expect(window.location.hash).toBe('');
    expect(window.location.search).not.toContain('code=');
    spy.mockRestore();
  });

  it('falls back to query-string oauth params', () => {
    window.history.replaceState({}, '', '/?status=200&code=foo&provider=github');
    const spy = jest.spyOn(root.user, 'authenticate');

    mount(
      <Provider>
        <Router>
          <ParseUrl />
        </Router>
      </Provider>
    );

    expect(spy).toHaveBeenCalledWith({ code: 'foo', provider: 'github' });
    expect(window.location.search).not.toContain('code=');
    spy.mockRestore();
  });

  it('prefers hash oauth params over the query string', () => {
    window.history.replaceState(
      {},
      '',
      '/?status=200&code=query-code&provider=bitbucket#status=200&code=hash-code&provider=github'
    );
    const spy = jest.spyOn(root.user, 'authenticate');

    mount(
      <Provider>
        <Router>
          <ParseUrl />
        </Router>
      </Provider>
    );

    expect(spy).toHaveBeenCalledWith({ code: 'hash-code', provider: 'github' });
    expect(window.location.hash).toBe('');
    expect(window.location.search).not.toContain('code=');
    spy.mockRestore();
  });
});
