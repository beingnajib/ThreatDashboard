import React from 'react';
import { render } from '@testing-library/react';
import DataAnalysis from './DataAnalysis';

test('renders DataAnalysis component', () => {
  const { getByText } = render(<DataAnalysis />);
  const linkElement = getByText(/Analyzed Data/i);
  expect(linkElement).toBeInTheDocument();
});
