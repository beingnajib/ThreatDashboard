import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import GenerateReport from './GenerateReport';

test('renders GenerateReport component', () => {
  const { getByText } = render(<GenerateReport />);
  const linkElement = getByText(/Generate Threat Report/i);
  expect(linkElement).toBeInTheDocument();
});

test('handles report format selection', () => {
  const { getByTestId } = render(<GenerateReport />);
  const selectInput = getByTestId('report-format-select');
  fireEvent.change(selectInput, { target: { value: 'PDF' } });
  expect(selectInput.value).toBe('PDF');
});
