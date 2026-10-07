import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { TitleBar } from '../components/TitleBar'

// Mock Tauri window
const mockMinimize = vi.fn().mockResolvedValue(undefined)
const mockClose = vi.fn().mockResolvedValue(undefined)
const mockOnView = vi.fn()
const mockOnLock = vi.fn()

vi.mock('@tauri-apps/api/window', () => ({
  getCurrentWindow: () => ({
    minimize: mockMinimize,
    close: mockClose,
    maximize: vi.fn().mockResolvedValue(undefined),
    unmaximize: vi.fn().mockResolvedValue(undefined),
    show: vi.fn().mockResolvedValue(undefined),
    hide: vi.fn().mockResolvedValue(undefined),
    setSize: vi.fn().mockResolvedValue(undefined),
    setPosition: vi.fn().mockResolvedValue(undefined),
    setResizable: vi.fn().mockResolvedValue(undefined),
    setAlwaysOnTop: vi.fn().mockResolvedValue(undefined),
    setTitle: vi.fn().mockResolvedValue(undefined),
    setSkipTaskbar: vi.fn().mockResolvedValue(undefined),
  }),
}))

describe('TitleBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockOnView.mockClear()
    mockOnLock.mockClear()
  })

  it('renders the TEAvault title', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByText('TEAvault')).toBeInTheDocument()
  })

  it('shows Locked badge when locked', () => {
    render(
      <TitleBar
        locked={true}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByText('Locked')).toBeInTheDocument()
    expect(screen.queryByText('Unlocked')).not.toBeInTheDocument()
  })

  it('shows Unlocked badge when unlocked', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByText('Unlocked')).toBeInTheDocument()
    expect(screen.queryByText('Locked')).not.toBeInTheDocument()
  })

  it('renders all four tabs when initialized and unlocked', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByRole('tab', { name: 'Keys' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Access' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Activity' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Settings' })).toBeInTheDocument()
  })

  it('does not render tabs when not initialized', () => {
    render(
      <TitleBar
        locked={false}
        initialized={false}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByText('TEAvault')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  })

  it('does not render tabs when locked even if initialized', () => {
    render(
      <TitleBar
        locked={true}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByText('TEAvault')).toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  })

  it('shows pending count badge on Access tab', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={3}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByRole('tab', { name: 'Access' })).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('hides pending badge when count is zero', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="access"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    const accessTab = screen.getByRole('tab', { name: 'Access' })
    expect(accessTab).toBeInTheDocument()
    // The badge should not appear when count is 0
    expect(screen.queryByText('0')).not.toBeInTheDocument()
  })

  it('calls onView when a tab is clicked', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    fireEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    expect(mockOnView).toHaveBeenCalledWith('settings')
  })

  it('calls onLock when lock button is clicked', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    const lockButton = screen.getByLabelText('Lock now')
    fireEvent.click(lockButton)
    expect(mockOnLock).toHaveBeenCalled()
  })

  it('hides lock button when already locked', () => {
    render(
      <TitleBar
        locked={true}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.queryByLabelText('Lock now')).not.toBeInTheDocument()
  })

  it('shows minimize and close buttons', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    expect(screen.getByLabelText('Minimise')).toBeInTheDocument()
    expect(screen.getByLabelText('Close')).toBeInTheDocument()
  })

  it('calls window.minimize on minimize button click', async () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    fireEvent.click(screen.getByLabelText('Minimise'))
    expect(mockMinimize).toHaveBeenCalled()
  })

  it('calls window.close on close button click', async () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    fireEvent.click(screen.getByLabelText('Close'))
    expect(mockClose).toHaveBeenCalled()
  })

  it('marks active tab with aria-selected', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="access"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    const keysTab = screen.getByRole('tab', { name: 'Keys' })
    const accessTab = screen.getByRole('tab', { name: 'Access' })
    expect(keysTab).toHaveAttribute('aria-selected', 'false')
    expect(accessTab).toHaveAttribute('aria-selected', 'true')
  })

  it('navigates with keyboard arrow keys', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="keys"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(mockOnView).toHaveBeenCalledWith('access')
  })

  it('wraps arrow navigation', () => {
    render(
      <TitleBar
        locked={false}
        initialized={true}
        pending={0}
        view="settings"
        onView={mockOnView}
        onLock={mockOnLock}
      />
    )
    const tablist = screen.getByRole('tablist')
    fireEvent.keyDown(tablist, { key: 'ArrowRight' })
    expect(mockOnView).toHaveBeenCalledWith('keys')
  })
})
