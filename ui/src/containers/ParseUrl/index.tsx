import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useMst } from '../../store/root';
import { Params } from '../../common/params';
import { AuthCodeProps, IError } from '../../store/auth';
import { readAuthCallbackParams, strippedAuthCallbackLocation } from '../../utils/updateUrl';

const ParseUrl: React.FC = () => {
  const { resources, user } = useMst();
  const history = useNavigate();

  const oauthParams = readAuthCallbackParams(window.location.search, window.location.hash);
  const status = oauthParams.get(Params.Status);
  const code = oauthParams.get(Params.Code);
  const provider = oauthParams.get(Params.Provider);

  if (status !== null || code !== null || provider !== null) {
    const next = strippedAuthCallbackLocation(
      window.location.pathname,
      window.location.search,
      window.location.hash
    );
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (next !== current) {
      // Strip the auth code from the address bar once so it is not kept in history.
      // replaceState does not re-render; gating on remaining params avoids a loop.
      window.history.replaceState(window.history.state, '', next);
    }
  }

  // It checks status and code and then redirect to authentication
  if (status === '200' && code !== null) {
    const codeFinal: AuthCodeProps = {
      code: code,
      provider: provider || undefined
    };
    user.authenticate(codeFinal);
    if (user.isAuthenticated) {
      // Initially `history.goBack` was used to go to the previous
      // page but with the update of `react-router-dom` version '-1'
      // is added so that the page redirects back to the previous page
      history('-1');
    }
  }
  // Display the alert message when status is not ok
  else if (!user.isAuthenticated && status !== '200' && status !== null) {
    // Wait to redirection of page and then update the store
    setTimeout(() => {
      const error: IError = {
        status: Number(status),
        serverMessage: 'Login Failed, Please Try To Login Again!',
        customMessage: ''
      };
      user.setErrorMessage(error);
    }, 1000);
  }

  const searchParams: URLSearchParams = new URLSearchParams(window.location.search);
  if (window.location.search) {
    if (searchParams.has(Params.Query)) {
      resources.setSearch(searchParams.get(Params.Query) || '');
    }
    if (searchParams.has(Params.Tag)) {
      const tags = searchParams.getAll(Params.Tag);
      resources.setSearch(`tags:${tags.join(',')}`);
      resources.setSearchedTags(searchParams.getAll(Params.Tag));
    }
    if (searchParams.has(Params.SortBy)) {
      resources.setSortBy(searchParams.get(Params.SortBy) || '');
    }
    // Storing url params to store inorder to parse the url only after successfully resource load
    resources.setURLParams(window.location.search);
  }
  return <> </>;
};
export default ParseUrl;
