import express, {ErrorRequestHandler} from 'express';
import morgan from 'morgan';
import {google} from 'googleapis';
import axios from 'axios';
import cors from 'cors';
import 'dotenv/config';
import {readFileSync} from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import url from 'node:url';
import qs from 'qs';
import {nanoid} from 'nanoid';

const app = express();

app.use(cors());
app.use(express.json());
// application/x-www-form-encoded 형태의 request body를 parsing 하기 위해 필요
app.use(express.urlencoded({extended: true}));

const port = process.env.PORT as string;
console.log(port);

app.get('/', (req, res, next) => {
  res.status(200).end();
});

app.use(morgan('dev'));

const appleServiceID = process.env.APPLE_SERVICE_ID ?? '';
const appleRedirectUri = process.env.APPLE_REDIRECT_URI ?? '';
const appleDeveloperTeamId = process.env.APPLE_DEVELOPER_TEAM_ID ?? '';
const applePrivateKeyFileName = process.env.APPLE_PRIVATE_KEY_FILENAME ?? '';
const applePrivateKeyId = process.env.APPLE_KEY_ID ?? '';

const googleClientID = process.env.GOOGLE_OAUTH_CLIENT_ID ?? '';
const googleRedirectUri = process.env.GOOGLE_REDIRECT_URI ?? '';
const googleClientSecret = process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? '';

app.get('/sign-in-with-google', (req, res, next) => {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');

  const queryParams = qs.stringify({
    client_id: googleClientID,
    redirect_uri: googleRedirectUri,
    response_type: 'code',
    scope: 'openid email',
    prompt: 'consent',
  });

  url.search = queryParams;

  res.redirect(url.toString());
});

app.get('/sign-in-with-apple', (req, res, next) => {
  const url = new URL('https://appleid.apple.com/auth/authorize');

  const queryParams = qs.stringify({
    client_id: appleServiceID,
    response_mode: 'form_post',
    response_type: 'code',
    scope: 'name email',
    redirect_uri: appleRedirectUri,
  });

  url.search = queryParams;

  res.redirect(url.toString());
});

app.get('/oauth2/google', async (req, res, next) => {
  try {
    console.log(req.query);
    const params = new URLSearchParams({
      client_id: googleClientID,
      client_secret: googleClientSecret,
      code: req.query.code as string,
      grant_type: 'authorization_code',
      redirect_uri: googleRedirectUri,
    });

    const tokenRequest = await axios.post(
      `https://oauth2.googleapis.com/token`,
      params.toString()
    );

    console.log('token exchange result', tokenRequest.data);

    res.status(200).send('ok');
  } catch (e) {
    next(e);
  }
});

app.post('/oauth2/apple', async (req, res, next) => {
  try {
    console.log('authorization result', req.body);
    const code = req.body.code as string;

    const privateKey = readFileSync(
      path.join(__dirname, applePrivateKeyFileName)
    );
    const currTime = Math.floor(Date.now() / 1000);

    const appleOAuthClientSecret = jwt.sign(
      {
        iss: appleDeveloperTeamId,
        iat: currTime,
        exp: currTime + 15777000,
        aud: 'https://appleid.apple.com',
        sub: appleServiceID,
      },
      privateKey,
      {
        algorithm: 'ES256',
        keyid: applePrivateKeyId,
      }
    );

    const params = qs.stringify({
      client_id: appleServiceID,
      client_secret: appleOAuthClientSecret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: appleRedirectUri,
    });

    const validateAuthorizationCodeRequest = await axios.post(
      'https://appleid.apple.com/auth/token',
      params
    );

    console.log('token exchange result', validateAuthorizationCodeRequest.data);

    res.status(200).send('ok');
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
