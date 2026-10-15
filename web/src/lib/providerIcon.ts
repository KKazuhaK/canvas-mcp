// Decode and rasterize uploads locally. Only the small, metadata-free PNG is sent.
export async function compressProviderIcon(file: File): Promise<string> {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type) || file.size > 5 * 1024 * 1024 || !file.size) throw new Error('invalid_icon')
  const image = await createImageBitmap(file)
  try {
    if (!image.width || !image.height || image.width * image.height > 16_777_216) throw new Error('invalid_icon')
    const canvas = document.createElement('canvas')
    const context = canvas.getContext('2d')
    if (!context) throw new Error('invalid_icon')
    for (const side of [256, 192, 128, 96, 64]) {
      const scale = Math.min(1, side / image.width, side / image.height)
      canvas.width = Math.max(1, Math.round(image.width * scale))
      canvas.height = Math.max(1, Math.round(image.height * scale))
      context.drawImage(image, 0, 0, canvas.width, canvas.height)
      const result = canvas.toDataURL('image/png')
      if (result.startsWith('data:image/png;base64,') && atob(result.split(',')[1]).length <= 65536) return result
    }
    throw new Error('invalid_icon')
  } finally {
    image.close()
  }
}
