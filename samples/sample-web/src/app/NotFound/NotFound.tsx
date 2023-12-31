import * as React from 'react';
import { ExclamationTriangleIcon } from '@patternfly/react-icons';
import {
  Button,
  EmptyState,
  EmptyStateBody,
  EmptyStateFooter,
  EmptyStateHeader,
  EmptyStateIcon,
  PageSection,
} from '@patternfly/react-core';
import { useHistory } from 'react-router-dom';

const NotFound: React.FunctionComponent = () => {
  function GoHomeBtn() {
    const history = useHistory();
    function handleClick() {
      history.push('/');
    }
    return (
      <Button onClick={handleClick}>Take me home</Button>
    );
  }

  return (
    <PageSection>
    <EmptyState variant="full">
      <EmptyStateHeader titleText="404 Page not found" icon={<EmptyStateIcon icon={ExclamationTriangleIcon} />} headingLevel="h1" />
      <EmptyStateBody>
        We didn&apos;t find a page that matches the address you navigated to.
      </EmptyStateBody><EmptyStateFooter>
      <GoHomeBtn />
    </EmptyStateFooter></EmptyState>
  </PageSection>
  )
};

export { NotFound };
