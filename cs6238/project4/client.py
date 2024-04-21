# pylint: disable=broad-exception-caught, missing-module-docstring, too-few-public-methods
import base64
import json
import os
import time
import requests
import jwt

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.hashes import SHA256

gt_username = 'hlyons8' #pylint: disable=invalid-name
SERVER_NAME = 'secure-shared-store'
CURRENT_PATH = os.path.dirname(__file__)
CLIENT_ID = "client1"

# These need to be created manually before you start coding.
NODE_CERTIFICATE = CURRENT_PATH + '/certs/' + CLIENT_ID + '.crt'
NODE_KEY = CURRENT_PATH + '/certs/' + CLIENT_ID + '.key'

# Dictionary to keep track of modified files
CHECKOUT_FILES = {}

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
    """
        node_certificate is the name of the certificate file of the client node (present inside certs).
        node_key is the name of the private key of the client node (present inside certs).
        body parameter should in the json format.
    """
    request_url = 'https://{}/{}'.format(server_name, action)
    request_headers = {
        'Content-Type': "application/json"
    }
    response = requests.post(
        url=request_url,
        data=json.dumps(body),
        headers=request_headers,
        cert=(node_certificate, node_key),
        verify="/home/cs6238/Desktop/Project4/CA/CA.crt",
        timeout=(10, 20),
    )
    with open(gt_username, 'wb') as f:
        f.write(response.content)

    return response

def sign_statement(statement : bytes, user_private_key_file : str) -> bytes:
    """
    Creates a signature for a statement with the given private key.
    """
    with open(user_private_key_file, "rb") as file:
        skey_bytes = file.read()

    skey = load_pem_private_key(skey_bytes, password=None)

    pad =  padding.PSS(padding.MGF1(SHA256()), padding.PSS.MAX_LENGTH)
    signed_statement = skey.sign(statement, padding=pad, algorithm=SHA256())

    return signed_statement

def login():
    """
    Logins the user to 3S Server.
    """
    successful_login = False

    while not successful_login:
        # get the user id from the user input or default to user1
        user_id = (input(" User Id: ") or "user1")

        # get the user private key filename or default to user1.key
        private_key_filename = (input(" Private Key Filename: ") or user_id)
        # complete the full path of the user private key filename (depends on the client)
        # Ex: '/home/cs6238/Desktop/Project4/client1/userkeys/' + private_key_filename
        user_private_key_file = CURRENT_PATH + '/userkeys/' + private_key_filename

        if not os.path.exists(user_private_key_file):
            print("Key file not found, try again")
            continue

        # create the statement
        statement = f"{CLIENT_ID} as {user_id} logs into the Server"
        statement_bytes = bytes(statement, "utf-8")

        signed_statement = sign_statement(statement_bytes, user_private_key_file)

        body = {
            'user-id': user_id,
            'statement': statement,
            'signed-statement': base64.b64encode(signed_statement).decode("utf8")
        }

        server_response = post_request(SERVER_NAME, 'login', body, NODE_CERTIFICATE, NODE_KEY)

        if server_response.json().get('status') == 200:
            successful_login = True
        else:
            print(server_response.json().get('message', "Try again"))

    return server_response.json()

def checkin_file(session_token, doc_id, security_flag, file_name):
    """
    Checks in a file to 3S Server.
    """
    with open(file_name, "rb") as file:
        file_data = file.read()

    encoded_data = base64.b64encode(file_data).decode("utf8")

    body = {
        'document-id': doc_id,
        'data': encoded_data,
        'security-flag': security_flag,
        'token': session_token,
    }

    server_response = post_request(SERVER_NAME, 'checkin', body, NODE_CERTIFICATE, NODE_KEY)
    status = server_response.json().get('status')

    if status == 200:
        if doc_id in CHECKOUT_FILES:
            del CHECKOUT_FILES[doc_id]

    return server_response

def checkin(session_token):
    """
    Checks in a document to 3S Server.
    """
    doc_id = (input(" Document Id: ") or "file1.txt")
    security_flag = (input(" Security Flag (1=Confidentiality, 2=Integrity): ") or "2")

    checkout_file_name = CURRENT_PATH + "/documents/checkout/" + doc_id
    checkin_file_name = CURRENT_PATH + "/documents/checkin/" + doc_id

    if os.path.exists(checkout_file_name):
        os.rename(checkout_file_name, checkin_file_name)

    if not os.path.exists(checkin_file_name):
        print("File does not exist")
        return

    if security_flag not in ["1", "2"]:
        print("Invalid security flag")
        return

    security_flag = int(security_flag)

    server_response = checkin_file(session_token, doc_id, security_flag, checkin_file_name)
    message = server_response.json().get("message")
    status = server_response.json().get('status')

    print(message)
    print(status)
    return

def checkout(session_token):
    """
    Checks out a document from 3S Server.
    """
    # get the user id from the user input or default to user1
    doc_id = (input(" Document Id: ") or "file1.txt")

    body = {
        'document-id': doc_id,
        'token': session_token,
    }

    server_response = post_request(SERVER_NAME, 'checkout', body, NODE_CERTIFICATE, NODE_KEY)
    message = server_response.json().get("message")
    status = server_response.json().get('status')

    if status == 200:
        file_data = base64.b64decode(server_response.json().get("file"))
        checkout_file_name = CURRENT_PATH + "/documents/checkout/" + doc_id

        with open(checkout_file_name, "wb") as file:
            file.write(file_data)

        CHECKOUT_FILES[doc_id] = time.time()

    print(message)
    print(status)
    return

def grant(session_token):
    """
    Grants a user access to a document managed by 3S Server.
    """
    # get the user id from the user input or default to user1
    doc_id = (input(" Document Id: ") or "file1.txt")
    target_user_id = (input(" Target User Id: ") or "user2")
    access_level = (input(" Access Level (1/2/3): ") or "1")
    duration = input(" Duration (seconds): " or 50)

    body = {
        'document-id': doc_id,
        'target-user-id': target_user_id,
        'access-level': access_level,
        'duration': duration,
        'token': session_token
    }

    server_response = post_request(SERVER_NAME, 'grant', body, NODE_CERTIFICATE, NODE_KEY)
    message = server_response.json().get("message")
    status = server_response.json().get('status')

    print(message)
    print(status)
    return

def delete(session_token):
    """
    Deletes a document from 3S Server.
    """

    # get the user id from the user input or default to user1
    doc_id = (input(" Document Id: ") or "file1.txt")

    body = {
        'document-id': doc_id,
        'token': session_token
    }

    server_response = post_request(SERVER_NAME, 'delete', body, NODE_CERTIFICATE, NODE_KEY)
    message = server_response.json().get("message")
    status = server_response.json().get('status')

    if status == 200:
        checkin_file_name = CURRENT_PATH + "/documents/" + doc_id
        checkout_file_name = CURRENT_PATH + "/documents/" + doc_id
        if os.path.exists(checkin_file_name):
            os.remove(checkin_file_name)
        if os.path.exists(checkout_file_name):
            os.remove(checkout_file_name)

    print(message)
    print(status)
    return

def logout(session_token):
    """
    Logs out the current user from 3S Server. Files in the checkin folder
    """

    doc_ids = os.listdir(CURRENT_PATH + "/documents/checkout")

    for doc_id in doc_ids:
        checkout_file_name = CURRENT_PATH + "/documents/checkout/" + doc_id

        if doc_id in CHECKOUT_FILES:
            last_modified = os.path.getmtime(checkout_file_name)
            if last_modified > CHECKOUT_FILES[doc_id]:
                print(f"Checking in document {doc_id}")

                server_response = checkin_file(session_token, doc_id, 2, checkout_file_name)

                message = server_response.json().get("message")
                status = server_response.json().get('status')

                print(message)
                print(status)

                if status == 200:
                    checkin_file_name = CURRENT_PATH + "/documents/checkin/" + doc_id
                    os.rename(checkout_file_name, checkin_file_name)

    body = {
        "token": session_token
    }

    server_response = post_request(SERVER_NAME, 'logout', body, NODE_CERTIFICATE, NODE_KEY)
    message = server_response.json().get("message")
    status = server_response.json().get('status')

    print(message)
    print(status)
    return

def valid_token(session_token: str) -> bool:
    """
    Verifies that the session token is still valid.
    """
    valid = False

    try:
        token = jwt.decode(session_token, options={"verify_signature": False})
        expires = token["exp"]
        if expires > time.time():
            valid = True
    except Exception as e:
        print(e)

    return valid

def print_main_menu():
    """
    print main menu
    :return: nothing
    """
    print(" Enter Option: ")
    print("    1. Checkin")
    print("    2. Checkout")
    print("    3. Grant")
    print("    4. Delete")
    print("    5. Logout")
    return

def main():
    """
        # TODO: Authenticate the user by calling login.
        If the login is successful, provide the following options to the user
            1. Checkin
            2. Checkout
            3. Grant
            4. Delete
            5. Logout
        The options will be the indices as shown above. For example, if user
        enters 1, it must invoke the Checkin function. Appropriate functions
        should be invoked depending on the user input. Users should be able to
        perform these actions in a loop until they logout. This mapping should
        be maintained in your implementation for the options.
    """

    # Initialize variables to keep track of progress
    server_message = 'UNKNOWN'
    server_status = 'UNKNOWN'
    session_token = 'UNKNOWN'
    is_login = False

    # test()
    # return
    login_return = login()

    server_message = login_return['message']
    server_status = login_return['status']
    session_token = login_return['session_token']

    print("\nThis is the server response")
    print(server_message)
    print(server_status)
    print(session_token)

    if server_status == 200:
        is_login = True

    while is_login:
        print_main_menu()
        user_choice = input()
        if not valid_token(session_token):
            print("Session expired - please login again")
            break
        if user_choice == '1':
            checkin(session_token)
        elif user_choice == '2':
            checkout(session_token)
        elif user_choice == '3':
            grant(session_token)
        elif user_choice == '4':
            delete(session_token)
        elif user_choice == '5':
            logout(session_token)
            is_login = False
        else:
            print('not a valid choice')

if __name__ == '__main__':
    main()
