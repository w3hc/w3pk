# Browser & Device Compatibility

This document details WebAuthn support across browsers, operating systems, and devices for w3pk.

---

## ✅ Fully Supported (95%+ of users)

### Desktop Browsers

| Browser | Minimum Version | Release Date | Platform | Features |
|---------|----------------|--------------|----------|----------|
| **Chrome** | 67+ | May 2018 | Windows, macOS, Linux | ✅ Full WebAuthn support |
| **Edge** | 18+ | November 2018 | Windows | ✅ Windows Hello integration |
| **Firefox** | 60+ | May 2018 | Windows, macOS, Linux | ✅ Full WebAuthn support |
| **Safari** | 14+ | September 2020 | macOS Big Sur (11.0+) | ✅ Touch ID integration |
| **Opera** | 54+ | June 2018 | Windows, macOS, Linux | ✅ Full WebAuthn support |
| **Brave** | 1.0+ | November 2019 | Windows, macOS, Linux | ✅ Full WebAuthn support |

### Mobile Browsers

| Platform | Minimum Version | Release Date | Authenticator |
|----------|----------------|--------------|---------------|
| **iOS Safari** | 14.5+ | April 2021 | ✅ Face ID / Touch ID |
| **iOS Chrome** | 14.5+ | April 2021 | ✅ Face ID / Touch ID |
| **iOS Edge** | 14.5+ | April 2021 | ✅ Face ID / Touch ID |
| **Android Chrome** | 70+ (Android 9+) | October 2018 | ✅ Fingerprint / Face Unlock |
| **Android Edge** | 45+ (Android 9+) | January 2020 | ✅ Fingerprint / Face Unlock |
| **Samsung Internet** | 11+ (Android 9+) | February 2020 | ✅ Fingerprint / Face Unlock |

### Operating Systems

| OS | Minimum Version | Release Date | Built-in Authenticator |
|----|----------------|--------------|------------------------|
| **Windows 10** | Build 1903+ | May 2019 | ✅ Windows Hello (PIN, Face, Fingerprint) |
| **Windows 11** | All versions | October 2021 | ✅ Windows Hello (Enhanced) |
| **macOS** | 10.15 Catalina+ | October 2019 | ✅ Touch ID (on supported Macs) |
| **iOS** | 14.5+ | April 2021 | ✅ Face ID / Touch ID |
| **iPadOS** | 14.5+ | April 2021 | ✅ Face ID / Touch ID |
| **Android** | 9.0 Pie+ | August 2018 | ✅ Biometric authentication |

---

## ❌ Not Supported / Limited

### Old Browsers

| Browser | Issue | Last Update |
|---------|-------|-------------|
| **Safari < 14** | No WebAuthn support | September 2020 |
| **Chrome < 67** | No WebAuthn support | May 2018 |
| **Firefox < 60** | No WebAuthn support | May 2018 |
| **Edge Legacy (< 18)** | Partial support only | November 2018 |
| **Internet Explorer 11** | Never supported WebAuthn | Retired June 2022 |
| **Opera < 54** | No WebAuthn support | June 2018 |

### Old Operating Systems

| OS | Issue | Release Date | End of Support |
|----|-------|--------------|----------------|
| **macOS < 10.15 Catalina** | Limited/no WebAuthn | October 2019 | September 2022 |
| **iOS < 14.5** | No resident credentials | April 2021 | Still supported for older devices |
| **iPadOS < 14.5** | No resident credentials | April 2021 | Still supported for older devices |
| **Android < 9.0** | Limited/no WebAuthn | August 2018 | Varies by manufacturer |
| **Windows < 10** | No Windows Hello | July 2015 | EOL January 2023 |
| **Windows 10 < 1903** | Limited Hello support | May 2019 | EOL December 2020 |

### Mobile Device Limitations

| Device | Issue | Notes |
|--------|-------|-------|
| **iPhone < 8** | No Face ID/Touch ID (iOS 14.5+) | Released September 2017 |
| **iPhone 6s/SE (1st gen)** | Touch ID only, iOS 14.5+ required | Released September 2015 |
| **iPad < 5th gen** | Limited biometric support | Released March 2017 |
| **Android phones < 2018** | Typically lack biometric APIs | Varies by manufacturer |

### Special Cases & Limitations

#### 🔴 **Never Works**

| Environment | Issue | Reason |
|-------------|-------|--------|
| **Safari Private Mode** | WebAuthn disabled | Apple privacy protection |
| **Firefox Private Mode** | Limited functionality | Privacy restrictions |
| **Incognito/Private browsing** | Credentials don't persist | No persistent storage |
| **WebView/Embedded browsers** | Often disabled | Security restrictions |
| **Node.js/Server-side** | No WebAuthn API | Browser-only API |

#### ⚠️ **May Not Work**

| Environment | Issue | Workaround |
|-------------|-------|------------|
| **Corporate/Managed devices** | Policy restrictions | Contact IT admin |
| **Chromebooks (old)** | Limited biometric support | Use PIN or external key |
| **Linux (some distros)** | No built-in authenticator | Use external security key |
| **VirtualBox/VMs** | No biometric passthrough | Use password fallback |
| **Remote Desktop** | Biometrics not forwarded | Use local device |

### Hardware Security Keys

| Key Type | CTAP Version | w3pk Support | Release Date |
|----------|--------------|--------------|--------------|
| **YubiKey 5 Series** | CTAP2 (FIDO2) | ✅ Full support | September 2018 |
| **YubiKey 4 Series** | CTAP1 (U2F only) | ⚠️ Limited | April 2015 - Discontinued |
| **Google Titan** | CTAP2 | ✅ Full support | August 2018 |
| **Feitian** | CTAP2 models | ✅ Full support | 2019+ |
| **Thetis** | CTAP2 | ✅ Full support | 2019+ |
| **Solo Key** | CTAP2 | ✅ Full support | 2019+ |

**Notes:**
- ⚠️ Older YubiKeys (< 5 series) use CTAP1/U2F and have limited functionality
- ⚠️ Some security keys require PIN setup
- ⚠️ NFC keys may not work on all devices

---

## 📊 Market Share (2025)

Based on current browser market share:

| Category | Support Level | Market Share |
|----------|---------------|--------------|
| **Fully Supported** | Chrome 67+, Safari 14+, etc. | ~95% |
| **Limited Support** | Older browsers, special cases | ~3% |
| **No Support** | IE11, very old browsers | ~2% |

---

## 🔍 Feature Detection

w3pk automatically detects WebAuthn support:

```typescript
// Automatic detection
const w3pk = createWeb3Passkey()

try {
  await w3pk.register({ username: 'alice' })
  // ✅ WebAuthn supported
} catch (error) {
  if (error.message.includes('WebAuthn not supported')) {
    // ❌ Browser too old
    showUpgradeBrowserMessage()
  }
}
```

Manual detection:

```typescript
// Check if WebAuthn is available
if (window.PublicKeyCredential) {
  console.log('✅ WebAuthn supported')

  // Check if platform authenticator is available
  const available = await PublicKeyCredential
    .isUserVerifyingPlatformAuthenticatorAvailable()

  if (available) {
    console.log('✅ Biometric authenticator available')
  } else {
    console.log('⚠️ No biometric - use external security key')
  }
} else {
  console.log('❌ WebAuthn not supported')
  console.log('Please upgrade your browser:')
  console.log('- Chrome 67+ (May 2018)')
  console.log('- Firefox 60+ (May 2018)')
  console.log('- Safari 14+ (September 2020)')
  console.log('- Edge 18+ (November 2018)')
}
```

---

## 🛠️ Troubleshooting

### "WebAuthn not supported"

**Possible causes:**
1. Browser too old (pre-2018)
2. Private/Incognito mode
3. Corporate policy blocking
4. Running in WebView/embedded browser

**Solutions:**
- Update browser to latest version
- Disable private browsing mode
- Use regular browser (not embedded)
- Contact IT if corporate device

### "No authenticator available"

**Possible causes:**
1. No biometric hardware (older device)
2. Biometrics not configured
3. Platform doesn't support WebAuthn

**Solutions:**
- Set up Face ID/Touch ID/Windows Hello
- Use external security key (YubiKey, etc.)
- Update to supported OS version

### "Credential not found"

**Possible causes:**
1. Credential created in different browser
2. Browser data cleared
3. Different user profile
4. Private browsing mode used

**Solutions:**
- Use same browser where registered
- Restore from mnemonic backup
- Re-register on this device

---

## 📱 Device-Specific Notes

### Apple Devices

**iCloud Keychain Sync:**
- iOS 14.5+, macOS 11.3+ with iCloud Keychain enabled
- Credentials sync across Apple devices automatically
- Requires same Apple ID
- End-to-end encrypted

**Touch ID Macs:**
- MacBook Pro (2016+)
- MacBook Air (2018+)
- iMac Pro (2017+)
- Mac mini (2018+)

**Face ID/Touch ID iPhones:**
- iPhone X+ (Face ID)
- iPhone 8/8 Plus and newer with Touch ID
- iPhone SE (2nd gen+)

### Windows Devices

**Windows Hello Requirements:**
- Windows 10 build 1903+ or Windows 11
- Compatible biometric hardware:
  - Fingerprint reader
  - IR camera (face recognition)
  - Or PIN (always available)

**Known Issues:**
- Some older fingerprint readers not compatible
- VM environments don't support Hello
- Remote Desktop doesn't forward biometrics

### Android Devices

**Biometric Requirements:**
- Android 9.0 (Pie) or higher
- Fingerprint sensor or face unlock
- Google Play Services up to date

**Known Issues:**
- Some manufacturers disable WebAuthn
- Older devices may lack biometric APIs
- Samsung Internet may work better than Chrome on Samsung devices

---

## 🔗 Additional Resources

- [WebAuthn Browser Support (Can I Use)](https://caniuse.com/webauthn)
- [FIDO Alliance Device Compatibility](https://fidoalliance.org/fido2/)
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Windows Hello Documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/)
- [Android Biometric Documentation](https://developer.android.com/training/sign-in/biometric-auth)

---

## 📝 Recommendations

### For Developers

1. **Always check availability** before using w3pk
2. **Provide fallbacks** for unsupported browsers
3. **Show clear error messages** with upgrade instructions
4. **Test on multiple platforms** (iOS, Android, Windows, macOS)
5. **Consider progressive enhancement** (WebAuthn if available, password otherwise)

### For Users

1. **Use modern browsers** (updated within last 2 years)
2. **Keep OS updated** to latest version
3. **Enable iCloud Keychain** (Apple devices) for sync
4. **Set up Windows Hello** (Windows devices)
5. **Back up mnemonic phrase** in case device is lost
6. **Avoid private browsing** for wallet operations

---

**Last Updated:** October 2025
**w3pk Version:** 0.6.0+
