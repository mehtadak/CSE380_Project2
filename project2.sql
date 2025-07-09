DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS Movies;
DROP TABLE IF EXISTS Genres;
DROP TABLE IF EXISTS Reviews;

CREATE TABLE Users(
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT NOT NULL PRIMARY KEY,
    email_address TEXT NOT NULL UNIQUE,
    moderator INTEGER NOT NULL,
    critic INTEGER NOT NULL,
    hashed_password TEXT NOT NULL,
    salt TEXT NOT NULL
);

CREATE TABLE Movies(
    public_id INTEGER NOT NULL UNIQUE,
    synopsis TEXT NOT NULL,
    title TEXT NOT NULL
);

CREATE TABLE Genres(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    genre text,
    movie_id INTEGER NOT NULL,
    FOREIGN KEY (movie_id) REFERENCES Movies(public_id) ON DELETE CASCADE
);

CREATE TABLE Reviews(
  review_id INTEGER NOT NULL PRIMARY KEY,
  rating INTEGER NOT NULL,
  review_text TEXT NOT NULL,
  movie_id INTEGER NOT NULL,
  user TEXT NOT NULL,
  FOREIGN KEY (movie_id) REFERENCES Movies(public_id) ON DELETE CASCADE,
  FOREIGN KEY (user) REFERENCES Users(username) ON DELETE CASCADE
);