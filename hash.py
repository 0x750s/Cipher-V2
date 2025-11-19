import bcrypt

def generate_hashes():
    accounts = {
        "Admin": "Password",
        "User": "password"
    }

    for username, plain_password in accounts.items():
        hashed = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt())
        print(f"{username} {hashed.decode()} admin 10000 999999" if username == "Admin" else f"{username} {hashed.decode()} normal 100 600")

if __name__ == "__main__":
    generate_hashes()
