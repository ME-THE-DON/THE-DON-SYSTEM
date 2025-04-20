import hashlib

# Function to verify the password
def verify_password(input_username, input_password):
    # Stored admin credentials (hashed)
    stored_username = "THE DON"
    stored_password_hash = hashlib.sha256("ALLAH@997$don".encode()).hexdigest()

    # Hash the input password and compare with stored hash
    input_password_hash = hashlib.sha256(input_password.encode()).hexdigest()

    if input_username == stored_username and input_password_hash == stored_password_hash:
        return True
    else:
        return False

# User login attempt
username = input("Enter username: ")
password = input("Enter password: ")

if verify_password(username, password):
    print("Login successful!")
else:
    print("Invalid credentials.")
