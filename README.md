> [!CAUTION]
> **Email verification is simulated in _development mode._**
> 
> After registration the verification link will appear in the server console.
> Copy and open it in your browser to activate the account.

# lemoniq 🍋 
## Web-Blog service uses **Go** for the backend, **HTML** for page structure, **CSS** for styling, **JavaScript** for client-side animation, and **JSON** for local data storage. :shipit:

#### *Lemoniq** is a creative blog-style web application built with **Go**, combining server-rendered pages, JWT-based authentication, email verification, article publishing, an admin dashboard, and a visually atmospheric interface with glassmorphism elements, video background, and animated rain effects.

#### It is a compact full-stack project that demonstrates how to build a content platform without an external database, using local JSON storage, modular handlers, middleware, and template-based rendering. At the same time, Lemoniq is more than just a technical exercise — it feels like a small digital space with its own mood, where backend structure and visual style work together instead of existing separately.

#### This project works especially well as a learning project, a portfolio piece, or a practical example of backend and full-stack development in Go. It brings together routing, authentication, role-based access control, CRUD logic, local persistence, and server-rendered UI in one structured application.

---

## Overview

Lemoniq is designed as a lightweight publishing platform where visitors can explore public content, register as users, verify their email, log in, access a personal account page, and create new articles. Administrators use a separate access flow to enter a protected dashboard where they can manage content, edit articles, and delete them when needed.

The application keeps its architecture intentionally simple and transparent:

- **Go** handles the backend and routing
- **HTML templates + CSS** render the frontend
- **JWT tokens in HttpOnly cookies** handle authentication
- **JSON files** store articles and user accounts
- **Environment variables** control secrets and admin credentials

One of the practical advantages of Lemoniq is that it does not require any database setup. The system automatically creates the required storage directories on startup and seeds a few base articles on the first launch, so the application already feels alive from the beginning rather than looking empty and unfinished.

<img width="120" height="120" alt="image" src="https://github.com/user-attachments/assets/d4ecab4f-878f-41c9-a662-ec943c25c1a2" />

---

## Features

Lemoniq includes the core features expected from a small content platform while keeping the codebase readable and approachable.

- User registration
- Login and logout
- Email verification flow
- JWT authentication with cookies
- Protected account page
- Public article feed
- Article creation for authenticated users
- Separate admin login flow
- Admin dashboard for content management
- Article editing and deletion by admin
- JSON-based local storage
- FAQ and About pages
- Animated landing page with video background
- Glassmorphism-inspired UI styling

Because the app uses file-based JSON storage instead of a database, it is easy to run locally and understand end-to-end without additional infrastructure. That makes it especially convenient for studying the full request flow and seeing how all the parts of the application connect together in a clear way.

---

## Tech Stack

- **Backend:** Go, `net/http`
- **Frontend:** HTML, CSS, Go templates
- **Authentication:** JWT + HttpOnly cookies
- **Storage:** Local JSON files
- **Configuration:** `.env` with `godotenv`
- **Architecture:** Modular handlers, middleware, and models


<img width="200" height="200" alt="image" src="https://github.com/user-attachments/assets/d4d1c92f-f517-48fd-8c37-f3fa398af873" />

---

## Project Architecture

The project is organized into a small and readable structure:

- `main.go` loads environment variables, ensures storage exists, registers routes, and starts the server
- `handlers/` contains route handlers and the main application logic
- `handlers/middleware/` contains JWT validation and route protection
- `model/` defines the core entities used by the application
- `HTML/` stores server-rendered templates
- `images/` stores static visual assets
- `articles/` stores article JSON files
- `users/` stores user JSON files

This structure keeps the project clear and easy to navigate, which is especially useful for learning, maintenance, and portfolio presentation. Even though the application is relatively compact, it already follows a modular approach that makes the logic feel organized rather than chaotic.

---

## Project Structure

```bash
.
├── main.go
├── handlers/
│   ├── account_handlers.go
│   ├── article_handlers.go
│   ├── auth.go
│   ├── email.go
│   ├── pages_handlers.go
│   ├── router.go
│   ├── storage.go
│   └── middleware/
│       └── jwt_middleware.go
├── model/
│   ├── article.go
│   └── user.go
├── HTML/
├── images/
├── articles/
├── users/
└── .env
```
## How It Works?

#### When the application starts, it first loads environment variables from the _.env_ file. After that, it initializes storage by creating the _articles_ and _users_ directories if they do not already exist. During the same step, the application also adds several starter articles so that the platform already contains visible content on first launch.

#### Once initialization is complete, the application registers all routes and starts the HTTP server on localhost:8080.

#### From that point, visitors can browse public pages, register an account, verify their email using the link printed in the server console, and log in. After authentication, users can access their personal account page and create new articles. Administrators follow a separate login flow and can open the dashboard, where they are able to edit or delete published content.

#### The overall flow is straightforward, but that is part of the project’s strength: it shows the full cycle of a small web platform without hiding the important logic behind unnecessary complexity.

## Authentication and Access  <img width="140" height="140" alt="image" src="https://github.com/user-attachments/assets/dd10ecbe-96b7-4c59-9ae3-8498820804da" />

#### Lemoniq uses JWT-based authentication stored in an HttpOnly cookie named auth_token. When a user logs in successfully, a token is generated and attached to the browser as a cookie. Protected routes are then checked through middleware, which validates the token and adds user data to the request context.

### The application separates access into different roles:

> Guests can browse public content and register

> Authenticated users can access their account page and publish articles

> Administrators have a separate protected area with dashboard access and content management privileges

#### Email verification is part of the user registration flow. After registration, the application generates a verification token and prints a confirmation link in the server console. The user must open this link before they are able to log in successfully.

#### This role-based structure makes the application feel more realistic and adds an important layer of logic beyond a basic single-user demo.

## Article Management

### Articles are stored as individual JSON files inside the articles directory. Each article contains an ID, title, content, publication date, author, and image path.

## The article flow includes:

> Automatic ID generation for new articles

> Default publish date when none is provided

> Default image fallback when no image is specified

>Article creation for authenticated users

>Article editing and deletion for administrators

> Automatic update of user post count when content is added or removed

### This keeps the publishing flow simple, but still realistic enough to demonstrate actual CRUD behavior. It also makes the content system easy to inspect during development, since every article can be viewed directly in storage as a separate JSON file.

> [!IMPORTANT]
># How to Run?                   
>
> <img width="190" height="190" alt="image" src="https://github.com/user-attachments/assets/7777e924-b808-4c0a-9bc1-656063290fba" />
>
>  ### To run the project locally, first install the required dependencies and make > sure the environment variables are configured.
>
> * Create a .env file in the root of the project and define the following values:
>
> * JWT_SECRET=your_secret_here
> * ADMIN_USERNAME=admin
> * ADMIN_PASSWORD=your_password_here
> 
> ### If these values are not provided, the application will still run using fallback defaults, but it is better to set them manually for proper local development.
>
> ## Then run:
>
> * go mod tidy
> * go run main.go
>
> ### Once the server starts, open the following address in your browser:
>
> http://localhost:8080
>
> ### After that, you can register a new user, confirm the account through the verification link printed in the console, and start exploring the app from both the user and admin side.  

# Storage

### Lemoniq uses local JSON-based storage instead of a database. User accounts are stored in the users directory, and articles are stored in the articles directory. Each file represents a single entity, which makes the storage logic simple and easy to inspect.

### This approach keeps the project lightweight and beginner-friendly while still demonstrating persistent data handling, content creation, and access-controlled actions. It is especially useful for educational purposes, local testing, and portfolio presentation, because the entire data layer remains visible and understandable.

<img width="370" height="370" alt="image" src="https://github.com/user-attachments/assets/ae488fa2-e275-4567-86c5-269a5a76b58e" />

# Why This Project Matters?

### Lemoniq is a small but complete web application that combines many essential concepts of modern backend and full-stack development in one place.

## It demonstrates:

> Routing

> Middleware

> Authentication

> Role-based authorization

> CRUD operations

> Server-side rendering

> Static file serving

> Local persistence

### Because of that, it works well not only as a study project, but also as a portfolio piece that shows both technical structure and a sense of product atmosphere. It is practical, understandable, and visually distinctive at the same time, which makes it more memorable than a purely technical demo.

# Future Improvements

## The current version of Lemoniq already covers the full basic flow of a content platform, but it also leaves room for future improvements.

### Possible next steps include:

> Integrating a real email delivery service

> Replacing SHA-256 password hashing with bcrypt

> Adding a database such as PostgreSQL or MySQL

> Introducing pagination and search for articles

> Supporting image uploads

>Improving admin moderation tools

>Adding password reset functionality

### These improvements would move the project from a clean educational and portfolio-ready application toward a more production-oriented platform, while keeping the same overall idea and structure.

![Screenshot of a comment on a GitHub issue showing an image, added in the Markdown, of an Octocat smiling and raising a tentacle.](https://camo.githubusercontent.com/13fff3442af824724acc42cefddf5c88a1675931fb089d5ff0bcdc95fc27c1ea/68747470733a2f2f73332e65752d63656e7472616c2d312e616d617a6f6e6177732e636f6d2f656e74676f2e696f2f6173736574732f676f706865725f67726170682e706e67)
