# TailorFlow — Backend API

The Express API for **TailorFlow**, a garment ordering and production-tracking platform. It provides endpoints for users, products, orders, checkout, role-aware operations, and shipment tracking.

**Frontend repository:** https://github.com/abd-005/Garments-Order-Production-Tracker-System-Frontend  
**Live application:** https://tailorflow-f0731.web.app

## Overview

This service uses MongoDB for application data, Firebase Admin SDK to verify Firebase ID tokens, and Stripe to create and retrieve Checkout sessions.

The API is implemented as a Node.js/Express application and includes a database-readiness gate intended to support serverless deployment.

## Core capabilities

- User registration records and profile retrieval
- Firebase ID-token verification middleware
- Role and account-status checks for buyer, manager, and admin operations
- Product listing with search, sorting, and pagination
- Product creation, updates, and deletion
- Cash-on-Delivery order creation
- Stripe Checkout session creation and payment-success processing
- Buyer order history and order cancellation
- Manager order approval/rejection workflows
- Tracking ID generation and tracking-event management
- Admin user listing, role updates, and account suspension

## Technology stack

- Node.js
- Express 5
- MongoDB Node.js driver
- Firebase Admin SDK
- Stripe SDK
- dotenv
- cors
- Node.js crypto module

## Getting started

### Prerequisites

- Node.js
- npm
- MongoDB database and connection string
- Firebase service-account JSON
- Stripe account and secret key

### Installation

```bash
git clone https://github.com/abd-005/Garments-Order-Production-Tracker-System-Backend.git
cd Garments-Order-Production-Tracker-System-Backend
npm install
```

### Environment variables

Create a `.env` file in the project root:

```env
PORT=5555
MONGODB_URI=your_mongodb_connection_string
FB_SERVICE_KEY=your_base64_encoded_firebase_service_account_json
STRIPE_SECRET_KEY=your_stripe_secret_key
CLIENT_DOMAIN=http://localhost:5173
```

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port; defaults to `5555` |
| `MONGODB_URI` | MongoDB connection string |
| `FB_SERVICE_KEY` | Base64-encoded Firebase service-account JSON |
| `STRIPE_SECRET_KEY` | Stripe secret API key |
| `CLIENT_DOMAIN` | Frontend origin used for CORS and Checkout redirects |

The service decodes `FB_SERVICE_KEY` from Base64 before initializing Firebase Admin. Keep the original service-account key and all secret values private. Do not commit `.env` or credentials.

### Run the API

```bash
npm start
```

The root endpoint responds with a simple server status message.

### Available scripts

| Command | Description |
|---|---|
| `npm start` | Start the API using Node.js |
| `npm run dev` | Intended development command using nodemon |

**Development-script note:** `package.json` currently references `nodemon` in the `dev` script, but nodemon is not listed as a dependency. Install it as a development dependency before relying on `npm run dev`, or use `npm start`.

The current `test` script is only a placeholder; an automated test suite is not configured yet.

## API route overview

The following is a high-level guide to the routes currently defined in `api/index.js`. Protected routes require a Firebase ID token in the Authorization header unless otherwise noted.

| Area | Example routes | Purpose |
|---|---|---|
| Health | `GET /` | Basic service response |
| Users | `POST /user`, `GET /user`, `GET /user/role` | Create/update user record and retrieve user information |
| Products | `GET /products`, `GET /product/:id` | Browse and retrieve products |
| Orders | `POST /cod-order`, `GET /my-orders`, `DELETE /orders/:orderId` | Buyer order operations |
| Checkout | `POST /create-checkout-session`, `POST /payment-success` | Stripe Checkout flow |
| Manager | `GET /manage-products`, `GET /pending-orders`, `PATCH /order/:id/status` | Product and order management |
| Admin | `GET /users`, `PATCH /update-role`, `PATCH /suspend-user` | Administrative user operations |
| Tracking | `POST /orders/:orderId/tracking`, `GET /orders/:orderId/tracking` | Add and retrieve tracking events |

This table is not an exhaustive API specification. Refer to `api/index.js` for the current route definitions, middleware order, request payloads, and response shapes.

## Data and authorization

- MongoDB database: `garmentsDB`
- Collections used: `users`, `products`, `orders`, and `trackings`
- Firebase Admin verifies incoming ID tokens.
- Role middleware checks the user's stored role and, for selected roles, approval status.
- Stripe Checkout sessions are created server-side.

## Deployment

The repository includes a `vercel.json` configuration for deployment and an `api/index.js` entry point. Deployment requires the environment variables above to be configured in the hosting provider.

## Engineering considerations

This codebase demonstrates API routing, middleware-based authentication and authorization, database operations, payment-provider integration, and order lifecycle handling.

It should not be considered a security-audited or production-hardened API. Review authorization on every resource-level operation, validate request payloads, add automated tests, and verify payment/order state transitions before using it with real customer data or payments.

## Related project

- [TailorFlow Frontend](https://github.com/abd-005/Garments-Order-Production-Tracker-System-Frontend)

## License

No license is currently specified for this repository.
