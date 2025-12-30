{
  "findings": [
    {
      "type": "Google API Key",
      "severity": "critical",
      "value_preview": "AIzaSyD-5_8gF...",
      "context": "apiKey: \"AIzaSyD-5_8gFp2aZ1m9K3rJ4d0eL6n7Q8w9x0y\"",
      "description": "This appears to be a Google API key based on its format (starts with 'AIza'). Hardcoding a Google API key in client-side JavaScript is dangerous as it can be exploited by malicious users to access paid APIs and exhaust quotas or rack up billing charges. This key should be stored securely on the server side. https://erikvanoosbree.nl/api-config.js"
    },
    {
      "type": "Bearer Token (JWT)",
      "severity": "critical",
      "value_preview": "eyJhbGciOiJIUz...",
      "context": "bearerToken: [10, 20, \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\", 40]",
      "description": "This looks like a portion of a JWT (JSON Web Token) included directly in a configuration object. This token could grant access to protected resources or services. Storing bearer tokens in frontend code violates secure authentication patterns and exposes your application to spoofing or privilege escalation. https://erikvanoosbree.nl/api-config.js"
    },
    {
      "type": "Internal API Endpoint",
      "severity": "medium",
      "value_preview": "https://api.bes...",
      "context": "apiEndpoint: \"https://api.bestapiendpointintheworld1.com/v1\"",
      "description": "This is a base API endpoint URL that appears to reveal internal API architecture. While not inherently a secret, exposing internal service URLs in client-side code can invite targeted enumeration or abuse attempts. Consider proxying calls through a backend if this endpoint is privileged. https://erikvanoosbree.nl/api-config.js"
    },
    {
      "type": "Google Analytics Tracking ID",
      "severity": "low",
      "value_preview": "UA-12345678-9",
      "context": "analyticsId: \"UA-12345678-9\"",
      "description": "This is a Google Analytics tracking ID. Although not a secret, publicly exposing this lets anyone send fake tracking data to your GA property. Use GA4 with enhanced security settings if needed. https://erikvanoosbree.nl/api-config.js"
    }
  ],
  "summary": "Found 4 potential issues: 1 Google API key (critical), 1 JWT access token (critical), 1 internal API URL (medium), and 1 analytics ID (low). Critical secrets must be removed from frontend code immediately to prevent abuse and data leakage."
}
