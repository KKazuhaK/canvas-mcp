import { afterEach, describe, expect, it, vi } from 'vitest'
import { compressProviderIcon } from './providerIcon'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('upload compression', () => {
  function bitmap(width = 1024, height = 512) {
    const image = { width, height, close: vi.fn() }
    vi.stubGlobal('createImageBitmap', vi.fn(async () => image))
    const drawImage = vi.fn()
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({ drawImage } as unknown as CanvasRenderingContext2D)
    const encode = vi.spyOn(HTMLCanvasElement.prototype, 'toDataURL').mockReturnValue('data:image/png;base64,aWNvbg==')
    return { image, drawImage, encode }
  }
  it.each(['image/png', 'image/jpeg', 'image/webp'])('resizes %s without stretching and closes decoded pixels', async (type) => {
    const { image, drawImage } = bitmap()
    expect(await compressProviderIcon(new File(['image'], 'icon', { type }))).toBe('data:image/png;base64,aWNvbg==')
    expect(drawImage).toHaveBeenCalledWith(image, 0, 0, 256, 128)
    expect(image.close).toHaveBeenCalledOnce()
  })
  it('reduces dimensions further when the first PNG exceeds the byte limit', async () => {
    const { image, drawImage, encode } = bitmap()
    encode.mockReturnValueOnce('data:image/png;base64,' + btoa('A'.repeat(65537)))
    await compressProviderIcon(new File(['image'], 'icon.png', { type: 'image/png' }))
    expect(drawImage).toHaveBeenLastCalledWith(image, 0, 0, 192, 96)
  })
  it('never enlarges a small image', async () => {
    const { image, drawImage } = bitmap(24, 12)
    await compressProviderIcon(new File(['image'], 'icon.png', { type: 'image/png' }))
    expect(drawImage).toHaveBeenCalledWith(image, 0, 0, 24, 12)
  })
  it('rejects unsupported, empty and oversized sources before decoding', async () => {
    bitmap()
    for (const file of [new File(['<svg/>'], 'icon.svg', { type: 'image/svg+xml' }), new File([], 'empty.png', { type: 'image/png' }), new File([new Uint8Array(5 * 1024 * 1024 + 1)], 'large.png', { type: 'image/png' })]) {
      await expect(compressProviderIcon(file)).rejects.toThrow('invalid_icon')
    }
    expect(createImageBitmap).not.toHaveBeenCalled()
  })
  it('rejects excessive decoded dimensions and still closes pixels', async () => {
    const { image } = bitmap(8192, 8192)
    await expect(compressProviderIcon(new File(['image'], 'icon.png', { type: 'image/png' }))).rejects.toThrow('invalid_icon')
    expect(image.close).toHaveBeenCalledOnce()
  })
})
