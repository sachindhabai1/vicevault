/**
 * VICEVAULT Firebase Admin Credentials Loader
 * Handles file, environment variable, or encoded fallback credentials.
 * Ensures the server NEVER crashes if service-account.json is missing on disk.
 */

const fs = require('fs');
const path = require('path');

const FALLBACK_B64 = 'ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsCiAgInByb2plY3RfaWQiOiAid2ViY29kZS01ZWNjYSIsCiAgInByaXZhdGVfa2V5X2lkIjogIjZkZjI3MjAzOTRhYzM4N2MwNzZjYzAxNjM4ZDM1NGU2YTExNWYwMjQiLAogICJwcml2YXRlX2tleSI6ICItLS0tLUJFR0lOIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRREJPdVJYVi9keWdNek1cbmpxMm5wS0lZbWJ1S1g5VHk3VlNNbHdyMTc3TkRuMnQ4VnowQ2FHQXQyZVpOMDNmd2dMQnpYOXhtYnZ5NTlPYjJcbjM5YThUbUg1cHJaMXBjVGVZa3FadjNkUEt6Q2w1ZWZ3MFJEUXF6NUFSdG1lS2szNExqeUo4eDNSWXJvckxyZHpcbkoyM1RubTdrdGpmQWhhRXZZZWZMQTc4MWZMbktmQ2FsaWkvalVNTCt4SWtoQ3d6d3E1UlBHbnVyYnJiOU9ubk5cbjc5c05LVEp5U2ZKZU1EOXpJZzNOSFVQUVo0VmQya3BGbkZiVkNzdGw3bUptWWxrV3ZWanRKSjJZczBRaW5uMldcbkR4STFtcUM5M0RISHBLZjNYOWxmdlhwdG9GLzZYT0c2M202WFlJUDM4M1dOdnJ5ZjRiMkFjY1ZjOGRBZXl2bkJcbkhpd3VWVjd0QWdNQkFBRUNnZ0VBQkJMdml3YmtCUEpCdnlOWDluT2laa1hoZmh5Z293R05lWXhhc3c0N2Q1Ykdcbkg2QkFQVXVCa1ozcFBPVlRQMHNiVFVkdFlHeUJJQk9SaGcxNG04NUVRd3o0aGxqNUlsNHNwL3F4TTRaYjEzZVdcbk1RM2JYcWJwb0ZYT0UwZGRqdmk4bG9UOWNUTjFiT0VtaFlORWpjUm1ucVJYM3hPQ0x6dFBkWWlOOEwwQk5zdG5cbldxSFBGTkc1aWtkaXNvMHZ1UzRCRW9SZ2pPbngzY0pjODdPZ1BYZ2xJMU9VZld3M2Fvb3htSFdJWDFuSVczVFNcblFDVG1Ld2hiaU1LeXlVNmx0Q2pQYm5aUmgyaENYQzZiNXhDN1VwZk1XUk1xdWZETDY1eTN0WE1JY0ZFM1BXb0lcblFrSGkvUXNyL2d1bG9yZW1OZ1NPYmFJeCtVQk9Fd3IwKzRJS213VTdjUUtCZ1FENzZLampNZ2JaZFM4T2I2V2Jcbk5YenJmNk0yNnZlSkEvZlNhalVvUExtbU14bTAzRm8vdllaTm5RZHBZWEUwNVRWa2VUcElmbjRPQktISDlORCtcbktpZEJkS3N0dTA4T0dXUXBjVmZVSHMwMkZHQlR0U3psTHBoTStPRzdkUFdFbzZwcnlrMHcxZm5SeTFqRGJqVU5cbko4am9ZY3UwU1dzRVdtSjdSYU5ZZGtxVHZRS0JnUURFWGtTMGQ3UjRTZ0RCbmhwbmhRcGtXUzNMcXpUWXRlcnZcblEyS0ZDTWVmKzgwekxYK3hHMEdYTnQ3UDhOc0tjTHlxcy9JWC9DSFRSRUxTVFZ2K3BlYitGWW41WXo1ZHNmaG5cbkFrYk5rWkc1UGJMdUgrVlVNWkpjdGFXZThtNmgrUW14SUhySEdmcFo4Y0VuRGgyamZQVUo0eHRxdGpDNUZUbzNcbnR2NTlBQUVTOFFLQmdRQ2UvbFc2TUJVS28xK3o2TnZKZnBUOXZtMnhkOVFNY3FpejhiempUSkNRU2FocjhyZ3pcbml0ZDluU0xVYkdBYlZwL0FicE5PdGlleGlWTGk5YTRDL1hBUmJDV3VrNDV1QTdDb1I1VjdtSVZGSU04N2hocHpcbi9GaThIRW05R3pEcktyR2hudW5oYk94a2NjZndjVnFpbHYzRFRoWllFQTZ2akt5anlXd3pwVldrc1FLQmdBMFNcbnBZcEtLZGFVUHFhbEt1YlhZWkM2cXlUUytncXZXYnVpQmM0TGZwYTFBYjAxZXpuRU1jS3FZWDBBY09TcUNyVm1cbmsyaHJYYWtkODBEaTY0dnhhWVppMHJPcW1yMU1HdGhvdTJQMkcvaDBGaFJxUlM4c3VheTRYeFZNMkhhcUNLNGxcbkZtZG80RlRhbGx4T1FVVGdEY1FodlhLR1BJb2wwcUZnNm1KUi9NQlJBb0dCQU1GRU5yQmFOUTNiUGJFZGpVbHFcbnd5WnFxRnFFU3o3bG83TDBybzJqS2ZiMWd0U1ZWeGljN1JhNWJKTkpvSHh2aWZ2UTltOEhIWERjWDFlRm5JaXhcbmdmd04yTkxSTmRLbFU1Z0UzeWFGcEZuNERwQVJ4QUlzVkRGcVhqUXpQOWtvbytweVAwTXpXSnEzSXUzazIzMTRcbkNxelluNExPcXF1M3htdkhDNWp6S005MVxuLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLVxuIiwKICAiY2xpZW50X2VtYWlsIjogImZpcmViYXNlLWFkbWluc2RrLWZic3ZjQHdlYmNvZGUtNWVjY2EuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLAogICJjbGllbnRfaWQiOiAiMTAzMTI0NDU2NTYxMjU2NjIwODEzIiwKICAiYXV0aF91cmkiOiAiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tL28vb2F1dGgyL2F1dGgiLAogICJ0b2tlbl91cmkiOiAiaHR0cHM6Ly9vYXV0aDIuZ29vZ2xlYXBpcy5jb20vdG9rZW4iLAogICJhdXRoX3Byb3ZpZGVyX3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vb2F1dGgyL3YxL2NlcnRzIiwKICAiY2xpZW50X3g1MDlfY2VydF91cmwiOiAiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vcm9ib3QvdjEvbWV0YWRhdGEveDUwOS9maXJlYmFzZS1hZG1pbnNkay1mYnN2YyU0MHdlYmNvZGUtNWVjY2EuaWFtLmdzZXJ2aWNlYWNjb3VudC5jb20iLAogICJ1bml2ZXJzZV9kb21haW4iOiAiZ29vZ2xlYXBpcy5jb20iCn0KCg==';

function getServiceAccount() {
  // 1. Try file path
  const customPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './service-account.json';
  const resolved = path.resolve(__dirname, customPath);
  if (fs.existsSync(resolved)) {
    try {
      return JSON.parse(fs.readFileSync(resolved, 'utf8'));
    } catch (e) {
      console.warn('⚠️ Could not parse service-account.json file:', e.message);
    }
  }

  // 2. Try environment variable FIREBASE_SERVICE_ACCOUNT (JSON or Base64)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } catch (e) {
      try {
        const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, 'base64').toString('utf8');
        return JSON.parse(decoded);
      } catch (e2) {}
    }
  }

  // 3. Try FIREBASE_SERVICE_ACCOUNT_BASE64
  if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
    try {
      const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
      return JSON.parse(decoded);
    } catch (e) {}
  }

  // 4. Try embedded fallback
  if (FALLBACK_B64) {
    try {
      const decoded = Buffer.from(FALLBACK_B64, 'base64').toString('utf8');
      return JSON.parse(decoded);
    } catch (e) {}
  }

  return null;
}

module.exports = { getServiceAccount };
