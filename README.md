# GitHub DecapCMS OAuth NodeJS Backend

This project is an Express server that handles OAuth authentication for GitHub + Decap CMS. It includes proper error handling, CSRF protection, and security headers to ensure a secure and reliable authentication flow.

## Features

- OAuth authentication for GitHub
- CSRF protection using tokens stored in cookies
- Secure headers to mitigate common web vulnerabilities
- Detailed error handling and logging

## Requirements

- Node.js (version 20 or later)

## Installation

1. Clone the repository.
2. Install the dependencies:

```sh
npm install
```

## Environment Variables

Provide the following environment variables:

```sh
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
ALLOWED_DOMAINS=example.com,*.example.org
```

## Running the server

Start the server with:

```sh
GITHUB_CLIENT_ID=your-github-client-id GITHUB_CLIENT_SECRET=your-github-client-secret ALLOWED_DOMAINS=example.com,*.example.org npm start
```

The server will be running on port 3000.

## OAuth Flow

1. Authorization Request: The client application redirects the user to /auth with the necessary query parameters.

Example:

```sh
GET /auth?provider=github&site_id=yourdomain.com
```

2. GitHub Authorization: The server redirects the user to GitHub's OAuth authorization endpoint.
3. Callback Handling: After the user authorizes the application, GitHub redirects back to the server's `/callback` endpoint with an authorization code.
4. Token Exchange: The server exchanges the authorization code for an access token.
5. Response: The server responds with an HTML page that communicates the result back to the client application.

## Routes

- GET /auth: Initiates the OAuth flow by redirecting to GitHub's authorization endpoint.
- GET /callback: Handles the OAuth callback and exchanges the authorization code for an access token.

## Security

- CSRF Protection: The server uses a CSRF token stored in a cookie to protect against CSRF attacks.
- Security Headers: The server sets various security headers to mitigate common web vulnerabilities.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any changes.

## Acknowledgements

- [Express](https://expressjs.com/)
- [Node.js](https://nodejs.org/)
- [GitHub OAuth](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [Sveltia CMS Auth](https://github.com/sveltia/sveltia-cms-auth)