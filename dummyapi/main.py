from fastapi import FastAPI
from fastapi.responses import JSONResponse
import json

app = FastAPI()

users=[]
groups=[]

user = {}
user["pw_name"] = "fake"
user["pw_passwd"] = "password"
user["pw_uid"] = 1234
user["pw_gid"] = 12345
user["pw_gecos"] = "fakeuser"
user["pw_dir"] = "/home/fake"
user["pw_shell"] = "/bin/bash"

group = {}
group["gr_name"] = "fakegroup"
group["gr_passwd"] = "secretpassword"
group["gr_gid"] = 12345

users.append(user)
groups.append(group)

def dict_to_string(dic):
    string = ""
    for key in dic:
        string = string + dic[key] +":"
    string = string [:-1]
    return string + ":"


@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return {"item_id": item_id}

@app.get("/user/id/{user_id}")
async def read_item(user_id: int):
    for user in users:
        if user["pw_uid"] == user_id:
            return JSONResponse(content=user)


@app.get("/user/name/{user_name}")
async def read_item(user_name: str):
    for user in users:
        if user["pw_name"] == user_name:
            return JSONResponse(content=user)

@app.get("/group/id/{group_id}")
async def read_item(group_id: int):
    for group in groups:
        if group["gr_gid"] == group_id:
            return JSONResponse(content=group)

@app.get("/group/name/{group_name}")
async def read_item(group_name: str):
    for group in groups:
        if group["gr_name"] == group_name:#
            return JSONResponse(content=group)