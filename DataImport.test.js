import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import DataImport from './DataImport';

test('renders DataImport component', () => {
  const { getByText } = render(<DataImport />);
  const linkElement = getByText(/Import Data/i);
  expect(linkElement).toBeInTheDocument();
});

test('triggers file upload on button click', () => {
  const { getByText } = render(<DataImport />);
  const button = getByText('Upload');
  fireEvent.click(button);
  expect(axios.post).toHaveBeenCalledTimes(1);
});
