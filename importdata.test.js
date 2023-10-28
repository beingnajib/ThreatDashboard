import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import ImportData from './ImportData';

test('renders ImportData component', () => {
  const { getByText } = render(<ImportData />);
  const linkElement = getByText(/Import Threat Data/i);
  expect(linkElement).toBeInTheDocument();
});

test('handles file upload', () => {
  const { getByTestId } = render(<ImportData />);
  const fileInput = getByTestId('file-upload');
  fireEvent.change(fileInput, { target: { files: [new File(['data'], 'data.csv', { type: 'text/csv' })] } });
  expect(fileInput.files[0]).toBe('data.csv');
});
