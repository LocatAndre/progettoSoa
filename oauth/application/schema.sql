DROP TABLE IF EXISTS ClientInformation;
DROP TABLE IF EXISTS UserInformation;
DROP TABLE IF EXISTS Request;
DROP TABLE IF EXISTS Code;
DROP TABLE IF EXISTS Token;
DROP TABLE IF EXISTS RefreshToken;
DROP TABLE IF EXISTS Serv;

CREATE TABLE IF NOT EXISTS ClientInformation(
    clientId string PRIMARY KEY,
    clientSecret string,
    user string NOT NULL,
    FOREIGN KEY (user) REFERENCES UserInformation (username)
);
CREATE TABLE IF NOT EXISTS Serv(
    id integer PRIMARY KEY AUTOINCREMENT,
    redirectUri string NOT NULL,
    scope string NOT NULL,
    user string NOT NULL,
    FOREIGN KEY (user) REFERENCES UserInformation (username)
);
CREATE TABLE IF NOT EXISTS UserInformation(
    username string PRIMARY KEY,
    password string NOT NULL
);
CREATE TABLE IF NOT EXISTS Request(
    reqId string PRIMARY KEY,
    clientId string,
    responseType string,
    redirectUri string,
    scope string,
    state string,
    FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId)
);
CREATE TABLE IF NOT EXISTS Code(
    authCode string PRIMARY KEY,
    clientId string,
    scope string,
    redirectUri string,
    FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId)
);
CREATE TABLE IF NOT EXISTS Token(
    clientId string,
    accessToken string,
    PRIMARY KEY(clientId, accessToken),
    FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId)
);
CREATE TABLE IF NOT EXISTS RefreshToken(
    clientSecret string,
    refreshToken string,
    PRIMARY KEY(clientSecret),
    FOREIGN KEY (clientSecret) REFERENCES ClientInformation (clientSecret)
);