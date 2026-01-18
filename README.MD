# Rate-Limited API Service

A Node.js/Express API service that protects endpoints from abuse by issuing API keys, enforcing per-user rate limits, and persisting state in PostgreSQL.

## Features

- User registration and API key generation
- API key-based authentication middleware
- Rate limiting (1000 requests per 15 minutes per API key)
- PostgreSQL persistence
- TypeScript support

## Tech Stack

- **Backend**: Node.js, Express.js, TypeScript
- **Database**: PostgreSQL
- **Security**: SHA-256 hashed API keys, timing-safe comparison
- **Rate Limiting**: express-rate-limit

## Prerequisites

- Node.js (v14+)
- PostgreSQL
- npm or yarn

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd rate-limited-api-service
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up PostgreSQL database and create a `.env` file with your database credentials:
   ```
   DB_HOST=localhost
   DB_DATABASE=postgres
   DB_USER=postgres
   DB_PASSWORD=your_password
   DB_PORT=5432
   ```

4. Run the database setup script:
   ```bash
   psql -U postgres -d postgres -f DB.sql
   ```

5. Start the server:
   ```bash
   npm start
   ```

The server runs on port 1000 by default (configurable via PORT env var).

## API Endpoints

### POST /signUp
Register a new user.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (201):**
```json
{
  "msg": {
    "id": 1,
    "email": "user@example.com",
    "created_at": "2023-..."
  }
}
```

### POST /apiKey/:id
Generate an API key for an existing user.

**Parameters:**
- `id`: User ID (from URL)

**Response (200):**
```json
{
  "msg": "generated-api-key-here"
}
```

### GET /data/:id
Access protected data (requires authentication).

**Headers:**
- `Authorization: Bearer <api-key>`

**Parameters:**
- `id`: User ID (must match authenticated user)

**Response (200):**
```json
{}
```

## Authentication

Include the API key in requests:
```
Authorization: Bearer your-api-key-here
```

## Rate Limiting

- **Limit**: 1000 requests per 15 minutes
- **Scope**: Per API key
- **Response**: 429 Too Many Requests

## Project Structure

- `Main.ts`: Main application file
- `DB.sql`: Database schema (if applicable)
- `package.json`: Dependencies and scripts

## Development

Run in development mode:
```bash
npm run dev
```

## Notes

This project demonstrates key concepts in API development:
- Secure API key authentication using SHA-256 hashing and timing-safe comparison
- Rate limiting to prevent abuse
- TypeScript generics for type-safe request/response handling
- PostgreSQL integration for data persistence
- Middleware for authentication and authorization

Key learnings:
- Always use strict equality (`===`) over loose (`==`)
- Hash sensitive data (like API keys) for security
- Use timing-safe comparisons to prevent timing attacks
- Specify generic types for better TypeScript support
- Handle errors gracefully with try/catch and appropriate status codes

## License

MIT
