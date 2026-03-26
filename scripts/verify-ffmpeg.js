const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

if (process.platform !== 'win32') {
  console.log(`Skipping ffmpeg verification for non-Windows platform: ${process.platform}`)
  process.exit(0)
}

const KNOWN_HASHES = {
  // Electron 41.0.4 ffmpeg.dll hashes per architecture
  CED08D56DA30DC9671C088870F8CD0820FB5B43D568BE5588D9934B883CCE43A: 'win32-arm64',
  BE391A7B7B36A43E6D3F6D20801B8410096888BF79BE08CE01CE224F17E0687F: 'win32-x64'
}

const ffmpegPath = path.join(__dirname, '../node_modules/electron/dist/ffmpeg.dll')

console.log('Validating ffmpeg.dll integrity...')
console.log(`Target: ${ffmpegPath}`)

if (!fs.existsSync(ffmpegPath)) {
  console.error('❌ ffmpeg.dll not found at expected path!')
  process.exit(1)
}

try {
  const fileBuffer = fs.readFileSync(ffmpegPath)
  const hashSum = crypto.createHash('sha256')
  hashSum.update(fileBuffer)
  const hex = hashSum.digest('hex').toUpperCase()

  if (!KNOWN_HASHES[hex]) {
    console.error('❌ SECURITY ALERT: ffmpeg.dll hash mismatch!')
    console.error(`Known hashes: ${Object.keys(KNOWN_HASHES).join(', ')}`)
    console.error(`Actual:       ${hex}`)
    console.error('\nPOSSIBLE CAUSES:')
    console.error('1. Electron version changed (update the hash in scripts/verify-ffmpeg.js)')
    console.error('2. File corruption')
    console.error('3. MALICIOUS TAMPERING (DLL Sideloading/Replacement)')
    process.exit(1)
  }

  console.log(`✅ ffmpeg.dll integrity check passed. (${KNOWN_HASHES[hex]})`)
  process.exit(0)
} catch (error) {
  console.error('❌ Error reading file:', error)
  process.exit(1)
}
