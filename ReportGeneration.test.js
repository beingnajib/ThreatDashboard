import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import ReportGeneration from './ReportGeneration';

test('renders ReportGeneration component', () => {
  const { getByText } = render(<ReportGeneration />);
  const linkElement = getByText(/Generate Report/i);
  expect(linkElement).toBeInTheDocument();
});

test('triggers report generation on button click', () => {
  const { getByText } = render(<ReportGeneration />);
  const button = getByText('Generate');
  fireEvent.click(button);
  expect(axios.post).toHaveBeenCalledTimes(1);
});
