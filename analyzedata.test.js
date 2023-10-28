import React from 'react';
import { render } from '@testing-library/react';
import AnalyzeData from './AnalyzeData';

test('renders AnalyzeData component', () => {
  const { getByText } = render(<AnalyzeData />);
  const linkElement = getByText(/Analyze Threat Data/i);
  expect(linkElement).toBeInTheDocument();
});
