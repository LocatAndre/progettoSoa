DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS user_team;
/*DROP TABLE IF EXISTS competition;*/
/*DROP TABLE IF EXISTS matches;*/
/*DROP TABLE IF EXISTS team;*/
DROP TABLE IF EXISTS player;

CREATE TABLE user (
    id integer PRIMARY KEY AUTOINCREMENT,
    username text NOT NULL,
    email text NOT NULL,
    password NOT NULL,
    otpSecret text NOT NULL,
    token_required integer NOT NULL DEFAULT 0 CHECK(token_required IN (0,1)),
    otp_required integer NOT NULL DEFAULT 1 CHECK(token_required IN (0,1))
);

CREATE TABLE user_team (
    id integer PRIMARY KEY AUTOINCREMENT,
    user_id integer NOT NULL,
    team_id integer NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE IF NOT EXISTS competition (
    id integer PRIMARY KEY NOT NULL,
    name text NOT NULL,
    nation text NOT NULL,
    currentMatchDay int NOT NULL DEFAULT 1,
    startComp date NOT NULL,
    endComp date NOT NULL 
);

CREATE TABLE IF NOT EXISTS matches(
    id integer PRIMARY KEY AUTOINCREMENT,
    competition int NOT NULL,
    matchday int NOT NULL,
    homeTeam int NOT NULL,
    awayTeam int NOT NULL,
    homeTeamScore int NOT NULL,
    awayTeamScore int NOT NULL,
    time time NOT NULL,
    dateMatch date NOT NULL,
    status text NOT NULL,
    FOREIGN KEY (competition) REFERENCES competition(id)
);

CREATE TABLE IF NOT EXISTS team (
    id integer PRIMARY KEY,
    name text NOT NULL,
    shortname text NOT NULL,
    tla text NOT NULL,
    logo text NOT NULL,
    venue text,
    founded text,
    clubColors text,
    website text
);

CREATE TABLE player (
    name text,
    position text,
    birth date,
    nationality text,
    role text
);