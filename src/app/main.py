#!/usr/bin/python3.6
# coding: utf-8
"""
version 1.0 Author: Ledivan B. Marques
            Email:    ledivan_bernardo@yahoo.com.br
"""
from json import loads
from pathlib import Path  # Import the Path class

import encryption
from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from yaml import dump

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})


@app.post("/", response_class=HTMLResponse)
async def seal_secret(
    request: Request,
    value: str = Form(...),
    namespace: str = Form(...),
    name: str = Form(...),
):
    try:
        encrypt = encryption.Encrypt()
        encrypted_value = encrypt.encrypt_value(namespace, name, value)
        return templates.TemplateResponse(
            "success.html",
            {"request": request, "json_output": encrypted_value},
        )
    except Exception as e:
        error_message = f"Error executing command: {e}"
        return templates.TemplateResponse(
            "error.html", {"request": request, "error_message": error_message}
        )


@app.get("/yaml", response_class=HTMLResponse)
async def show_form(request: Request, yaml: str = Form(default="")):
    return templates.TemplateResponse("yaml.html", {"request": request, "yaml": yaml})


class InvalidInputFormatError(ValueError):
    pass


@app.post("/yaml", response_class=HTMLResponse)
async def seal_yaml_secret(
    request: Request,
    value: str = Form(...),
    namespace: str = Form(...),
    name: str = Form(...),
):
    data_dict = {}
    encrypt = encryption.Encrypt()
    lines = value.strip().split("\n")
    try:
        for line in lines:
            if "=" not in line:
                raise InvalidInputFormatError(
                    "Invalid input format the value should be in the format key=value."
                )
            key, value = line.split("=")
            data_dict[key] = value

        encrypted_value = encrypt.get_sealed_secret(namespace, name, data_dict)
        json_dict = loads(encrypted_value)
        yaml_data = dump(json_dict, default_flow_style=False)

        return templates.TemplateResponse(
            "success.html", {"request": request, "json_output": yaml_data}
        )
    except InvalidInputFormatError as e:
        error_message = str(e)
        return templates.TemplateResponse(
            "error.html", {"request": request, "error_message": error_message}
        )
    except Exception as e:
        error_message = f"Error processing input: {e}"
        return templates.TemplateResponse(
            "error.html", {"request": request, "error_message": error_message}
        )


@app.get("/health")
def health_check():
    return {"status": "ok"}


# Serve the logo.png file from the 'static' directory
@app.get("/logo.png")
async def get_logo():
    logo_path = Path(__file__).parent / "static" / "logo.png"
    return FileResponse(logo_path)
