DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS preferences;

CREATE TABLE user (
    id integer PRIMARY KEY AUTOINCREMENT,
    username text NOT NULL,
    email text NOT NULL,
    password NOT NULL
);

CREATE TABLE preferences (
    id integer PRIMARY KEY AUTOINCREMENT,
    user_id integer NOT NULL,
    team_id integer NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);