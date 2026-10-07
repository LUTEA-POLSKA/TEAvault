import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { KeysPanel } from '../components/KeysPanel'

const mockEntries = [
  {
    id: 'entry-1',
    name: 'OPENAI_API_KEY',
    provider: 'OpenAI',
    description: 'primary model access',
    capabilities: ['llm', 'embeddings'],
    granted: true,
    hidden: false,
    category: 'llm',
    display_name: 'OpenAI',
    available: true,
    updated_at: '2025-01-01T00:00:00Z',
  },
  {
    id: 'entry-2',
    name: 'INTERNAL_SECRET',
    provider: 'Internal',
    capabilities: ['internal'],
    granted: false,
    hidden: true,
    display_name: 'Acme',
    available: true,
    updated_at: '2025-01-02T00:00:00Z',
  },
]

const mockCallbacks = {
  onAdd: vi.fn(),
  onEdit: vi.fn(),
  onCopy: vi.fn(),
  onDelete: vi.fn(),
  onGoToAccess: vi.fn(),
  onSetCategory: vi.fn(),
}

describe('KeysPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.values(mockCallbacks).forEach((cb) => cb.mockClear())
  })

  it('renders all entries', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument()
    expect(screen.getByText('INTERNAL_SECRET')).toBeInTheDocument()
  })

  it('shows provider for each entry', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByText('OpenAI')).toBeInTheDocument()
    expect(screen.getByText('Internal')).toBeInTheDocument()
  })

  it('shows capability badges', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByText('llm')).toBeInTheDocument()
    expect(screen.getByText('internal')).toBeInTheDocument()
  })

  it('shows granted badge when granted', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    // The granted entry should have a "granted" badge
    expect(screen.getByText('granted')).toBeInTheDocument()
  })

  it('shows hidden indicator when hidden', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByText('hidden')).toBeInTheDocument()
  })

  it('calls onAdd when add button is clicked', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /add a key/i }))
    expect(mockCallbacks.onAdd).toHaveBeenCalled()
  })

  it('calls onEdit when edit button is clicked', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    const editButton = screen.getAllByRole('button', { name: /edit/i })[0]
    fireEvent.click(editButton)
    expect(mockCallbacks.onEdit).toHaveBeenCalled()
  })

  it('calls onCopy when copy button is clicked', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    const copyButtons = screen.getAllByRole('button', { name: /copy/i })
    expect(copyButtons).toHaveLength(2)
    fireEvent.click(copyButtons[0])
    expect(mockCallbacks.onCopy).toHaveBeenCalled()
  })

  it('calls onDelete when delete button is clicked', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i })
    expect(deleteButtons).toHaveLength(2)
    fireEvent.click(deleteButtons[0])
    expect(mockCallbacks.onDelete).toHaveBeenCalled()
  })

  it('shows empty state when no entries', () => {
    render(
      <KeysPanel
        entries={[]}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByText(/no keys/i)).toBeInTheDocument()
  })

  it('shows search input', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    expect(screen.getByLabelText(/search/i)).toBeInTheDocument()
  })

  it('filters entries by search term', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    const searchInput = screen.getByLabelText(/search/i)
    fireEvent.change(searchInput, { target: { value: 'OPENAI' } })
    expect(screen.getByText('OPENAI_API_KEY')).toBeInTheDocument()
    expect(screen.queryByText('INTERNAL_SECRET')).not.toBeInTheDocument()
  })

  it('groups entries by category', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    // Entry with category should be under the category header
    expect(screen.getByText('llm')).toBeInTheDocument()
  })

  it('groups uncategorized entries under Uncategorized', () => {
    render(
      <KeysPanel
        entries={mockEntries}
        pendingCount={0}
        {...mockCallbacks}
      />
    )
    // Entry without category should be under Uncategorized
    expect(screen.getByText('Uncategorized')).toBeInTheDocument()
  })
})

