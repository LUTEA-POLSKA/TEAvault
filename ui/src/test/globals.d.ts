// Type declarations for test frameworks
declare module "vitest" {
  function describe(name: string, fn: () => void): void
  function it(name: string, fn: () => void | Promise<void>): void
  function it(name: string, timeout: number, fn: () => void | Promise<void>): void
  function expect<T>(value: T): any
  function beforeEach(fn: () => void | Promise<void>): void
  function afterEach(fn: () => void | Promise<void>): void
  function beforeAll(fn: () => void | Promise<void>): void
  function afterAll(fn: () => void | Promise<void>): void
  const vi: any
  namespace vi {
    function fn<T>(impl?: T): T & { mock: any }
  }
}

declare module "@testing-library/react" {
  import { ReactElement } from "react"
  export function render(ui: ReactElement, options?: any): any
  export const screen: any
  export const fireEvent: any
  export function waitFor(fn: () => void | Promise<void>, options?: any): Promise<void>
}

declare module "@testing-library/jest-dom/vitest" {}
