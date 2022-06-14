from fastapi import FastAPI

app = FastAPI()

users=[]
groups=[]

user = {}
user["w_name"] = "fake"
user["w_passwd"] = "passord"
user["w_uid"] = "1234"
user["w_gid"] = "12345"
user["w_gecos"] = "fakeuser"
user["w_dir"] = "/home/fake"
user["w_shell"] = "/bin/bash"

group = {}
group["gr_name"] = "fakegroup"
group["gr_passwd"] = "benus"
group["gr_gid"] = "12345"

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
async def read_item(user_id: str):
    for user in users:
        if user["w_uid"] == user_id:
            return{dict_to_string(user)}


@app.get("/user/name/{user_name}")
async def read_item(user_name: str):
    for user in users:
        if user["w_name"] == user_name:
            return{dict_to_string(user)}

@app.get("/group/id/{group_id}")
async def read_item(group_id: str):
    for group in groups:
        if group["gr_gid"] == group_id:
            return{dict_to_string(group)}

@app.get("/group/name/{group_name}")
async def read_item(group_name: str):
    for group in groups:
        if group["gr_name"] == group_name:
            return{dict_to_string(group)}