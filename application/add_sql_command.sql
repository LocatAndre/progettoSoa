DROP TABLE if EXISTS user;
DROP TABLE if EXISTS user_team;

CREATE TABLE user (
    id integer PRIMARY KEY AUTOINCREMENT,
    username text NOT NULL,
    email text NOT NULL,
    password NOT NULL,
    otpSecret text NOT NULL
);

CREATE TABLE user_team (
    id integer PRIMARY KEY AUTOINCREMENT,
    user_id integer NOT NULL,
    team_id integer NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);