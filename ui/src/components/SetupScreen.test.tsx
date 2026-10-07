import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { SetupScreen } from '../components/SetupScreen'

describe('SetupScreen', () => {
  const mockOnCreated = vi.fn().mockResolvedValue(undefined)

  beforeEach(() => {
    vi.clearAllMocks()
    mockOnCreated.mockClear()
  })

  it('renders the title', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    expect(screen.getByText('Create your vault')).toBeInTheDocument()
  })

  it('shows the no-recovery callout', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    expect(screen.getByText('There is no way to recover this')).toBeInTheDocument()
    expect(
      screen.getByText('If you lose the passphrase, the keys are gone. Write it down first.')
    ).toBeInTheDocument()
  })

  it('renders two password fields', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const labels = screen.getAllByLabelText(/passphrase|repeat/i)
    expect(labels).toHaveLength(2)
    expect(labels[0]).toHaveTextContent(/master passphrase/i)
    expect(labels[1]).toHaveTextContent(/repeat/i)
  })

  it('disables submit button when passphrase is too short', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    expect(submitBtn).toBeDisabled()
  })

  it('disables submit button when passphrases do not match', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'a' .repeat(15) } })
    fireEvent.change(repeatInput, { target: { value: 'different' } })
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    expect(submitBtn).toBeDisabled()
  })

  it('enables submit button when valid', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'a' .repeat(15) } })
    fireEvent.change(repeatInput, { target: { value: 'a' .repeat(15) } })
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    expect(submitBtn).not.toBeDisabled()
  })

  it('shows character count', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'abc' } })
    expect(screen.getByText('3 / 12')).toBeInTheDocument()
  })

  it('shows length error when passphrase is too short', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'abc' } })
    expect(screen.getByText('At least 12 characters.')).toBeInTheDocument()
  })

  it('shows match error when passphrases do not match', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'validpassphrase123' } })
    fireEvent.change(repeatInput, { target: { value: 'wrong' } })
    expect(screen.getByText('The two do not match.')).toBeInTheDocument()
  })

  it('clears match error when passphrases are corrected', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'validpassphrase123' } })
    fireEvent.change(repeatInput, { target: { value: 'wrong' } })
    expect(screen.getByText('The two do not match.')).toBeInTheDocument()
    fireEvent.change(repeatInput, { target: { value: 'validpassphrase123' } })
    expect(screen.queryByText('The two do not match.')).not.toBeInTheDocument()
  })

  it('calls onCreated when form is submitted with valid data', async () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'validpassphrase123' } })
    fireEvent.change(repeatInput, { target: { value: 'validpassphrase123' } })
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    fireEvent.click(submitBtn)
    await waitFor(() => {
      expect(mockOnCreated).toHaveBeenCalledWith('validpassphrase123')
    })
  })

  it('shows error when onCreated rejects', async () => {
    mockOnCreated.mockRejectedValue(new Error('Vault already exists'))
    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'validpassphrase123' } })
    fireEvent.change(repeatInput, { target: { value: 'validpassphrase123' } })
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    fireEvent.click(submitBtn)
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
      expect(screen.getByText('Vault already exists')).toBeInTheDocument()
    })
  })

  it('shows loading state during creation', async () => {
    let resolve: () => void
    const promise = new Promise<void>((r) => { resolve = r })
    mockOnCreated.mockReturnValue(promise)

    render(<SetupScreen onCreated={mockOnCreated} />)
    const [passInput, repeatInput] = screen.getAllByLabelText(/passphrase/i)
    fireEvent.change(passInput, { target: { value: 'validpassphrase123' } })
    fireEvent.change(repeatInput, { target: { value: 'validpassphrase123' } })
    const submitBtn = screen.getByRole('button', { name: /create the vault/i })
    fireEvent.click(submitBtn)

    expect(submitBtn).toHaveAttribute('loading', 'true')

    resolve!()
    await waitFor(() => {
      expect(mockOnCreated).toHaveBeenCalledTimes(1)
    })
  })

  it('allows empty inputs without errors', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    // No errors should appear with empty fields
    expect(screen.queryByText('At least 12 characters.')).not.toBeInTheDocument()
    expect(screen.queryByText('The two do not match.')).not.toBeInTheDocument()
  })

  it('renders the callout with critical tone', () => {
    render(<SetupScreen onCreated={mockOnCreated} />)
    // The callout should be present
    const callout = screen.getByText('There is no way to recover this')
    expect(callout).toBeInTheDocument()
  })
})
