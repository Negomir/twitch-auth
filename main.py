import os
import json
from fastapi import FastAPI, APIRouter
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from loguru import logger

from twitchAuth.code_grant_flow import CodeGrantFlow
from twitchAuth.token import Token, TokenStore
from twitchAuth.session import SessionStore
from twitchAuth.implicit_grant_flow import ImplicitGrantFlow
from twitchAuth.exceptions import *

client_id = os.environ["client_id"]
if not client_id:
    raise KeyError("client_id env is missing")

client_secret = os.environ["client_secret"]
if not client_secret:
    raise KeyError("client_secret env is missing")

redirect = os.environ["redirect_url"]
if not redirect:
    raise KeyError("redirect uri env is missing")

cgf = CodeGrantFlow(TokenStore(), SessionStore(), client_id, client_secret, redirect)

oauth = FastAPI()
app = FastAPI()

@oauth.middleware("http")
async def error_handler(req, call_next):
    fail = {"status": "fail"}

    try:
        return await call_next(req)
    except SessionNotFoundException as ex:
        logger.exception(ex)

        error = {
            "message": "session doesn't exist with given id",
            "type": "session_not_found",
            "code": 404,
        }

        return JSONResponse(content={**fail, "error": error}, status_code=404)
    except TokenNotFoundException as ex:
        logger.exception(ex)

        error = {
            "message": "session with given id doesn't have required twitch token",
            "type": "token_not_found",
            "code": 403,
        }

        return JSONResponse(content={**fail, "error": error}, status_code=403)
    except Exception as ex:
        logger.exception(ex)

        error = {
            "message": "something unexpected happened",
            "type": "internal_server_error",
            "code": 500
        }

        return JSONResponse(content={**fail, "error": error}, status_code=500)

@oauth.post("/sessions")
async def create_session(scopes: list[str] = []):
    session = cgf.new_session(scopes=scopes)
    data = json.dumps(session, default=lambda o: o.__dict__)
    return JSONResponse(content={"status": "ok","session": data}, status_code=201)

@oauth.get("/sessions/{session_id}/url")
async def get_auth_url(session_id: str):
    return JSONResponse(content={"status": "ok", "url": cgf.auth_url(session_id)}, status_code=200)

app.mount("/api/v1/twitch/oauth", oauth, "oauth")
