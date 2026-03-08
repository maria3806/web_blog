# Articles JSON API (Go)

This project is a simple JSON REST API written in Go, which allows you to create, read, update, and delete articles.
All articles are stored as separate .json files on the local filesystem. :woman_technologist:
#### The project was created as a learning / educational task to demonstrate working with: 

* Go web servers

* JSON serialization and deserialization

* HTTP methods (CRUD)

* File system operations

![Screenshot of a comment on a GitHub issue showing an image, added in the Markdown, of an Octocat smiling and raising a tentacle.](https://go.dev/images/gophers/ladder.svg)

# Features

* Start a web server on port 8080

* Automatically creates sample data on first run

<sub> and also </sub>
### CRUD operations for articles:

* Create article

* Get all articles

* Get article by ID

* Update article

* Delete article

* Data stored in the articles/ folder as JSON files

# Article Structure

### Each article has the following structure:
```
{
  "id": 1,
  "title": "First article",
  "content": "Hello world",
  "date": "2025-01-01"
}
```
# API Endpoints

![Screenshot of a comment on a GitHub issue showing an image, added in the Markdown, of an Octocat smiling and raising a tentacle.](https://go.dev/images/gophers/megaphone-gopher.svg)

### Get all articles
```
GET /articles
```

### Get article by ID
```
GET /articles?id=1
```

### Create a new article
```
POST /articles
```


### Request body example:
```
{
  "title": "New article",
  "content": "Some text",
  "date": "2025-02-01"
}
```

### Update an article
```
PUT /articles/{id}
```


### Request body example:
```
{
  "title": "Updated title",
  "content": "Updated content",
  "date": "2025-02-02"
}
```
### Delete an article
```
DELETE /articles/{id}
```

![Screenshot of a comment on a GitHub issue showing an image, added in the Markdown, of an Octocat smiling and raising a tentacle.](https://go.dev/images/gophers/skateboarding.svg)
# How to Run 

-  Make sure Go is installed

-  Clone the repository

-  Run the project:
```
go run main.go
```

## Server will start on:
> http://localhost:8080

# Technologies Used

> Go (Golang)

> net/http

> encoding/json

> File system storage

# Notes / Planned Features

_I plan to add additional features to make the API more convenient and closer to a real-world application. First, I want to implement search and filtering, pagination, and sorting for easier browsing of articles. I also plan to add an author field and allow filtering by author._

_In the future, it will be possible to implement database storage instead of JSON files, authentication for creating and editing articles, support for attachments (files, images), and interactive API documentation. These enhancements will make the project more functional and scalable while keeping it educational._

![Screenshot of a comment on a GitHub issue showing an image, added in the Markdown, of an Octocat smiling and raising a tentacle.](https://camo.githubusercontent.com/13fff3442af824724acc42cefddf5c88a1675931fb089d5ff0bcdc95fc27c1ea/68747470733a2f2f73332e65752d63656e7472616c2d312e616d617a6f6e6177732e636f6d2f656e74676f2e696f2f6173736574732f676f706865725f67726170682e706e67)
