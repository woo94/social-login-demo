import express, {ErrorRequestHandler} from 'express';
import morgan from 'morgan';
import {google} from 'googleapis';
import axios from 'axios';
import cors from 'cors';
import 'dotenv/config';
import {readFileSync} from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';

const app = express();

app.use(cors());
app.use(express.json());

const port = process.env.PORT as string;
console.log(port);

app.get('/', (req, res, next) => {
  res.status(200).end();
});

app.use(morgan('dev'));

// Client로부터 Authorization code를 전달받고
// Google Authorization Server에 요청을 보내 이것을 ID token으로 교환해 옵니다.
app.post('/oauth2/google', async (req, res, next) => {
  try {
    const googleOAuthClientId = process.env.GOOGLE_OAUTH_CLIENT_ID as string;
    const gooelOAuthClientSecret = process.env
      .GOOGLE_OAUTH_CLIENT_SECRET as string;
    const googleRedirectURI = process.env.GOOGLE_REDIRECT_URI as string;

    const params = new URLSearchParams({
      client_id: googleOAuthClientId,
      client_secret: gooelOAuthClientSecret,
      code: req.body.code,
      grant_type: 'authorization_code',
      redirect_uri: googleRedirectURI,
    });

    const tokenRequest = await axios.post(
      `https://oauth2.googleapis.com/token`,
      params.toString()
    );

    res.status(200).send(tokenRequest.data);
  } catch (e) {
    next(e);
  }
});

app.post('/oauth2/apple', async (req, res, next) => {
  try {
    const appleOAuthClientId = process.env.APPLE_OAUTH_CLIENT_ID as string;
    const appleDeveloperTeamId = process.env.APPLE_DEVELOPER_TEAM_ID as string;
    const appleKeyId = process.env.APPLE_KEY_ID as string;
    const appleRedirectURI = process.env.APPLE_REDIRECT_URI as string;
    const code = req.body.code as string;

    const privateKeyFileName = process.env
      .APPLE_OAUTH_CLIENT_SECRET_FILENAME as string;
    const privateKey = readFileSync(path.join(__dirname, privateKeyFileName));
    const currTime = Math.floor(Date.now() / 1000);

    const appleOAuthClientSecret = jwt.sign(
      {
        iss: appleDeveloperTeamId,
        iat: currTime,
        exp: currTime + 15777000,
        aud: 'https://appleid.apple.com',
        sub: appleOAuthClientId,
      },
      privateKey,
      {
        algorithm: 'ES256',
        keyid: appleKeyId,
      }
    );

    const params = new URLSearchParams({
      client_id: appleOAuthClientId,
      client_secret: appleOAuthClientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: appleRedirectURI,
    });

    const validateAuthorizationCodeRequest = await axios.post(
      'https://appleid.apple.com/auth/token',
      params.toString()
    );

    res.status(200).json(validateAuthorizationCodeRequest.data);
  } catch (e) {
    next(e);
  }
});

const errorHandler: ErrorRequestHandler = async (err, req, res, next) => {
  console.log(err);
  res.status(500).json(err);
};

app.use(errorHandler);

app.listen(Number(port), () => {
  console.log(`server is running on port ${port}`);
});
