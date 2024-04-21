# pylint: disable=broad-exception-caught, missing-module-docstring, too-few-public-methods
import base64
import json
import os
import re
import time
import traceback
import jwt

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from flask import Flask, request, jsonify
from flask_restful import Resource, Api

class LoginFailedError(Exception):
    '''
    Login failure exception type.
    '''
    def __init__(self, message : str):
        super().__init__(message)

class IntegrityCheckError(Exception):
    '''
    Integrity check failure exception type.
    '''
    def __init__(self, message : str):
        super().__init__(message)

class AccessDeniedError(Exception):
    '''
    Access denied exception type.
    '''
    def __init__(self, message : str):
        super().__init__(message)

class ArgumentError(Exception):
    '''
    Invalid argument exception type.
    '''
    def __init__(self, message : str):
        super().__init__(message)

class NotFoundError(Exception):
    '''
    File not found exception type.
    '''
    def __init__(self, message : str):
        super().__init__(message)

class Constants:
    '''
    Global constants.
    '''
    # Protection levels
    NONE = 0
    CONFIDENTIAL = 1
    INTEGRITY = 2

    # Access rights
    ANY_USER = "0"
    CHECKIN = 1
    CHECKOUT = 2
    ALL = 3

    # Token parameters
    NEVER = -1
    TOKEN_LIFETIME_HOURS = 2
    TOKEN_ISSUER = "3SServer"

class ServerUtils:
    '''
    Implements general utilities, such as argument checkers.
    '''
    def __init__(self):
        pass

    def valid_flag(self, flag : int) -> bool:
        '''
        Validates the security-flag request parameter.
        '''
        return flag in [Constants.CONFIDENTIAL, Constants.INTEGRITY]

    def valid_uid(self, uid : str) -> bool:
        '''
        Validates the user-id request parameter.
        '''
        return re.match("^[0-9a-zA-Z_\\-]+$", uid) is not None

    def valid_did(self, did : str) -> bool:
        '''
        Validates the document-id request parameter.
        '''
        return re.match("^[0-9a-zA-Z_\\-]+([.][0-9a-zA-Z]+){0,4}$", did) is not None
    
    def valid_access_level(self, level : int) -> bool:
        '''
        Validates the access-level request parameter.
         '''
        return level in [1, 2, 3]

    def valid_statement(self, statement : str, uid: str) -> bool:
        '''
        Validates the statement plaintext parameter.
        '''
        pattern = "^[0-9a-zA-Z]+ as ([0-9a-zA-Z]+) logs into the Server$"
        match = re.match(pattern, statement)

        if match is None:
            return False
            
        return match.group(1) == uid

class crypto_manager:
    '''
    3S Server cryptographic utilities.
    '''
    def __init__(self):
        pass

    def encrypt(self, key : bytes, data : bytes) -> bytes:
        '''
        Encrypts data with the given key.
        '''
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

        padder = sym_padding.PKCS7(128).padder()
        pad_data = padder.update(data) + padder.finalize()

        encryptor = cipher.encryptor()
        return encryptor.update(pad_data) + encryptor.finalize(), iv

    def decrypt(self, key : bytes, iv : bytes, data : bytes) -> bytes:
        '''
        Decrypts data with the given key and initialization vector.
        '''
        unpadder = sym_padding.PKCS7(128).unpadder()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        pad_data = decryptor.update(data) + decryptor.finalize()

        data = unpadder.update(pad_data) + unpadder.finalize()
        return data

    def generate_key(self, key_id : int = 0) -> bytes:
        '''
        Generates a key for symmetric encryption and optionally persists it to a file.
        '''
        if key_id < 0:
            raise ArgumentError("Invalid key_id")

        if key_id == 0:
            return os.urandom(32)

        key_file_name = "/home/cs6238/Desktop/Project4/server/application/keys/" + str(key_id) + ".key"
        dir_name = "/home/cs6238/Desktop/Project4/server/application/keys"

        if os.path.isfile(key_file_name):
            with open(key_file_name, "rb") as file:
                encrypted_key_bytes = file.read()

            key_bytes = self.decrypt_with_server_key(encrypted_key_bytes)
        else:
            key_bytes = os.urandom(32)
            encrypted_key_bytes = self.encrypt_with_server_key(key_bytes)

            if not os.path.exists(dir_name):
                os.mkdir(dir_name)

            with open(key_file_name, "wb") as file:
                file.write(encrypted_key_bytes)

        return key_bytes

    def encrypt_with_server_key(self, data : bytes) -> bytes:
        '''
        Encrypts data with the 3S Server public key.
        '''
        public_key_file = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub'

        with open(public_key_file, "rb") as file:
            key_bytes = file.read()

        key = load_pem_public_key(key_bytes)
        pad = padding.OAEP(mgf=padding.MGF1(SHA256()), algorithm=SHA256(), label=None)

        encrypted_data = key.encrypt(data, pad)
        return encrypted_data

    def decrypt_with_server_key(self, encrypted_data : bytes) -> bytes:
        '''
        Decrypts data with the 3S Server private key.
        '''
        private_key_file = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key'

        with open(private_key_file, "rb") as file:
            key_bytes = file.read()

        key = load_pem_private_key(key_bytes, password=None)
        pad = padding.OAEP(mgf=padding.MGF1(SHA256()), algorithm=SHA256(), label=None)

        data = key.decrypt(encrypted_data, pad)
        return data

    def sign_with_server_key(self, data : bytes) -> bytes:
        '''
        Creates a signature with the 3S Server private key.
        '''
        private_key_file = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.key'

        with open(private_key_file, "rb") as file:
            key_bytes = file.read()

        key = load_pem_private_key(key_bytes, password=None)

        signature = key.sign(
            data,
            padding=padding.PSS(
                mgf=padding.MGF1(SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), 
            algorithm=SHA256())

        return signature

    def verify_with_server_key(self, signature : bytes, data : bytes):
        '''
        Verifies a signature with the 3S Server public key.
        '''
        public_key_file = '/home/cs6238/Desktop/Project4/server/certs/secure-shared-store.pub'
        self.verify_with_key(public_key_file, signature, data)

    def verify_with_key(self, public_key_file : str, signature : bytes, data : bytes):
        '''
        Verifies a signature with the given public key.
        '''
        with open(public_key_file, "rb") as file:
            key_bytes = file.read()

        key = load_pem_public_key(key_bytes)
        ok = False
        try:
            key.verify(signature, 
                    data,            
                    padding=padding.PSS(
                        mgf=padding.MGF1(SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ), 
                    algorithm=SHA256())
            ok = True
        except Exception:
            pass

        if not ok:
            raise IntegrityCheckError("Signature validation failed")

class SessionManager:
    '''
    3S Server user session manager. Handles login, logout, and session token operations.
    '''
    def __init__(self):
        self._crypto = crypto_manager()
        self._skey = self._crypto.generate_key(42).hex()
        self._sessions = {}

    def login_with_statement(self, statement : str, signed_statement : bytes, user_id : str) -> str:
        '''
        Logins the user with a signed statement, and issues a session token if the login succeeded.
        '''
        utils = ServerUtils()

        if not utils.valid_uid(user_id):
            raise LoginFailedError("Invalid uid")

        if not utils.valid_statement(statement, user_id):
            raise LoginFailedError("Invalid statement")
        
        user_public_key_file = '/home/cs6238/Desktop/Project4/server/application/userpublickeys/' + user_id + '.pub'

        if not os.path.exists(user_public_key_file):
            raise LoginFailedError("Unknown user")

        statement_bytes = bytes(statement, encoding="UTF-8")
        self._crypto.verify_with_key(user_public_key_file, signed_statement, statement_bytes)        
        session_token = self._generate_session_token(user_id)
        return session_token

    def login_with_token(self, token : str) -> str:
        '''
        Logins a user with a session token.
        '''
        utils = ServerUtils()
        msg = None

        try:
            decoded_token = jwt.decode(jwt=token, key=self._skey, algorithms=["HS256"])
        except jwt.exceptions.InvalidSignatureError:
            msg = "Invalid signature"
        except jwt.exceptions.ExpiredSignatureError:
            msg = "Token expired"
        except Exception:
            msg = "Invalid token"

        if msg is not None:
            raise LoginFailedError(msg)

        issued_at = decoded_token['iat']
        issuer = decoded_token["iss"]
        user_id = decoded_token['uid']

        if issuer != Constants.TOKEN_ISSUER:
            raise LoginFailedError("Invalid issuer")

        if not utils.valid_uid(user_id):
            raise LoginFailedError("Invalid uid")

        if user_id in self._sessions:
            if issued_at != self._sessions[user_id]:
                raise LoginFailedError("Token invalidated by other login")
        else:
            self._sessions[user_id] = issued_at

        return user_id
    
    def logout(self, token : str) -> str:
        '''
        Logs out a user.
        '''
        user_id = self.login_with_token(token)

        if user_id in self._sessions:
            del self._sessions[user_id]

    def _generate_session_token(self, user_id : str) -> str:
        issued_at = int(time.time())
        expires_time = issued_at + Constants.TOKEN_LIFETIME_HOURS*3600

        token = {
            "iat": issued_at,
            "iss": Constants.TOKEN_ISSUER,
            "uid": user_id, 
            "exp": expires_time
        }

        self._sessions[user_id] = issued_at
        return jwt.encode(payload=token, key=self._skey, algorithm="HS256")

class AccessControl:
    '''
    3S Server access control functions.
    '''
    def __init__(self, values : dict = None):
        if values is None:
            self.owner = Constants.ANY_USER
            self.grant_uid = Constants.ANY_USER
            self.grant_level = Constants.NONE
            self.grant_expires = Constants.NEVER
        else:
            self.grant_expires = values["grant_expires"]
            self.grant_level = values["grant_level"]
            self.grant_uid = values["grant_uid"]
            self.owner = values["owner"]

    def is_owner(self, user_id : str) -> bool:
        '''
        Checks if the given user is the owner of this entry.
        '''
        return self.owner == user_id or self.owner == Constants.ANY_USER

    def get_access(self, user_id : str) -> int:
        '''
        Gets a user access level for this entry.
        '''
        if self.is_owner(user_id):
            return Constants.ALL
        
        if self.grant_uid in (user_id, Constants.ANY_USER):
            if self.grant_expires > int(time.time()):
                return self.grant_level
            if self.grant_expires == Constants.NEVER:
                return self.grant_level

        return Constants.NONE

    def check_access(self, user_id : str, level : int) -> bool:
        '''
        Verifies that a user has an access right in this entry.
        '''
        current = self.get_access(user_id)
        return (current & level) > 0

    def grant_access(self, target_user_id: str, level: int, duration: int):
        '''
        Grants a user an access right to this entry. Existing grants are replaced.
        '''
        expires = int(time.time()) + duration
        self.grant_uid = target_user_id
        self.grant_level = level
        self.grant_expires = expires            

class FileProtection:
    '''
    File protection data structure.
    '''
    def __init__(self, values : dict = None):
        if values is None:
            self.security_flag = Constants.INTEGRITY
            self.key = ""
            self.iv = ""
        else:
            self.iv = values["iv"]
            self.key = values["key"]
            self.security_flag = values["security_flag"]

class FileMetadata:
    '''
    File metadata data structure.
    '''
    def __init__(self, values : dict = None):
        if values is None:
            self.AccessControl = AccessControl()
            self.FileProtection = FileProtection()
        else:
            self.AccessControl = AccessControl(values["AccessControl"])
            self.FileProtection = FileProtection(values["FileProtection"])

class DocumentManager:
    '''
    3S Server document manager. Handles file checkout, checkin, grant, and delete operations.
    '''
    def __init__(self):
        self._crypto = crypto_manager()
        self._metadata = self._load_metadata()

    def checkin(self, user_id : str, doc_id : str, raw_data : bytes, security_flag : int):
        '''
        Checks in a file from a user and sets the protection level.
        '''
        utils = ServerUtils()

        valid_input = \
            utils.valid_uid(user_id) and \
            utils.valid_did(doc_id) and \
            utils.valid_flag(security_flag)

        if not valid_input:
            raise ArgumentError("Bad request")

        metadata = self._metadata.get(doc_id, FileMetadata())

        if self._doc_exists(doc_id):
            self._verify_access(user_id, doc_id, Constants.CHECKIN)

        if metadata.AccessControl.owner == Constants.ANY_USER:
            metadata.AccessControl.owner = user_id

        metadata.FileProtection.security_flag = security_flag

        self._metadata[doc_id] = metadata

        file_name = self._get_doc_path(doc_id)
        self._save_file(file_name, raw_data, doc_id)
        self._save_metadata()

    def checkout(self, user_id:str, doc_id:str) -> bytes:
        '''
        Checks out a file for a user.
        '''
        utils = ServerUtils()

        valid_input = \
            utils.valid_uid(user_id) and \
            utils.valid_did(doc_id)

        if not valid_input:
            raise ArgumentError("Bad request")

        if not self._doc_exists(doc_id):
            raise NotFoundError("File not found")

        self._verify_access(user_id, doc_id, Constants.CHECKOUT)

        if doc_id not in self._metadata:
            metadata = FileMetadata()
            metadata.FileProtection.security_flag = Constants.NONE
            self._metadata[doc_id] = metadata

        file_name = self._get_doc_path(doc_id)
        raw_data = self._load_file(file_name, doc_id)

        return raw_data
    
    def grant_access(self, user_id : str, doc_id: str, target_user_id : str, access_level : int, duration : int):
        '''
        Grants a user access to a file.
        '''
        utils = ServerUtils()

        valid_input = \
            utils.valid_uid(user_id) and \
            utils.valid_did(doc_id) and \
            utils.valid_uid(target_user_id) and \
            utils.valid_access_level(access_level) and \
            duration >= 0

        if not valid_input:
            raise ArgumentError("Bad request")

        if not self._doc_exists(doc_id):
            raise NotFoundError("File not found")

        self._verify_owner(user_id, doc_id)

        metadata = self._metadata[doc_id]
        metadata.AccessControl.grant_access(target_user_id, access_level, duration)
        self._metadata[doc_id] = metadata
        self._save_metadata()

    def delete(self, user_id : str, doc_id : str):
        '''
        Deletes a file.
        '''
        utils = ServerUtils()
 
        valid_input = \
            utils.valid_uid(user_id) and \
            utils.valid_did(doc_id)

        if not valid_input:
            raise ArgumentError("Bad request")
        
        if not self._doc_exists(doc_id):
            raise NotFoundError("File not found")

        self._verify_owner(user_id, doc_id)
        self._delete_doc(doc_id)

        if doc_id in self._metadata:
            del self._metadata[doc_id]
        
        self._save_metadata()

    def _verify_owner(self, user_id : str, doc_id : str):
        if doc_id in self._metadata:
            metadata = self._metadata[doc_id]
            authorized = metadata.AccessControl.is_owner(user_id)
        elif self._doc_exists(doc_id):
            authorized = True
        else:
            authorized = False

        if not authorized:
            raise AccessDeniedError("User is not authorized to perform operation")

    def _verify_access(self, user_id : str, doc_id : str, level : int):
        if doc_id in self._metadata:
            metadata = self._metadata[doc_id]
            authorized = metadata.AccessControl.check_access(user_id, level)
        elif self._doc_exists(doc_id):
            authorized = True
        else:
            authorized = False

        if not authorized:
            raise AccessDeniedError("User is not authorized to perform operation")

    def _metadata_from_dict(self, d : dict):
        output = {}
        for k in d:
            output[k] = FileMetadata(d[k])
        return output

    def _load_metadata(self) -> dict:
        output = {}
        metadata_file = "/home/cs6238/Desktop/Project4/server/data/metadata.json"

        if os.path.exists(metadata_file):
            raw_data = self._load_file(metadata_file)
            d = json.loads(raw_data)
            output = self._metadata_fromDict(d)

        return output
    
    def _get_doc_path(self, doc_id : str) -> str:
        return "/home/cs6238/Desktop/Project4/server/application/documents/" + doc_id

    def _doc_exists(self, doc_id : str):
        file_name = self._get_doc_path(doc_id)
        return os.path.exists(file_name)

    def _save_metadata(self):
        metadata_file = "/home/cs6238/Desktop/Project4/server/application/data/metadata.json"
        dir_name = "/home/cs6238/Desktop/Project4/server/application/data"

        if not os.path.exists(dir_name):
            os.mkdir(dir_name)

        metadata_str = json.dumps(self._metadata, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        metadata_bytes = bytes(metadata_str, "utf-8")
        self._save_file(metadata_file, metadata_bytes)

    def _save_file(self, file_name : str, raw_data : bytes, doc_id : str = None):
        metadata = None
        signature_file = file_name + ".signature"

        if doc_id is not None:
            metadata = self._metadata[doc_id]

        if metadata is not None:
            security_flag = metadata.FileProtection.security_flag
        else:
            security_flag = Constants.INTEGRITY

        key = b""
        iv = b""

        if security_flag == Constants.INTEGRITY:
            signature = self._crypto.sign_with_server_key(raw_data)
            signature = base64.b64encode(signature)

            with open(file_name, "wb") as file:
                file.write(raw_data)

            with open(signature_file, "wb") as file:
                file.write(signature)
        elif security_flag == Constants.CONFIDENTIAL:
            key = self._crypto.generate_key()
            encrypted_data, iv = self._crypto.encrypt(key, raw_data)
            key = self._crypto.encrypt_with_server_key(key)

            with open(file_name, "wb") as file:
                file.write(encrypted_data)

            if os.path.exists(signature_file):
                os.remove(signature_file)

        if metadata is not None:
            metadata.FileProtection.key = base64.b64encode(key).decode("utf-8")
            metadata.FileProtection.iv = base64.b64encode(iv).decode("utf-8")
            self._metadata[doc_id] = metadata

    def _load_file(self, file_name : str, doc_id : str = None) -> bytes:
        signature_file = file_name + ".signature"

        if doc_id is not None:
            protection = self._metadata[doc_id].FileProtection
            security_flag = protection.security_flag
        elif os.path.exists(signature_file):
            security_flag = Constants.INTEGRITY
        else:
            security_flag = Constants.NONE

        with open(file_name, "rb") as file:
            raw_data = file.read()

        if security_flag == Constants.INTEGRITY:
            with open(signature_file, "rb") as file:
                signature = file.read()
            signature = base64.b64decode(signature)
            self._crypto.verify_with_server_key(signature, raw_data)
        elif security_flag == Constants.CONFIDENTIAL:
            encrypted_key = base64.b64decode(protection.key)
            key = self._crypto.decrypt_with_server_key(encrypted_key)
            iv = base64.b64decode(protection.iv)
            raw_data = self._crypto.decrypt(key, iv, raw_data)

        return raw_data
    
    def _delete_doc(self, doc_id):
        file_name = self._get_doc_path(doc_id)
        signature_file = file_name + ".signature"

        if os.path.exists(file_name):
            os.remove(file_name)

        if os.path.exists(signature_file):
            os.remove(signature_file)

# Global variables
user_manager = SessionManager()
doc_manager = DocumentManager()

class Welcome(Resource):
    '''
    Welcome API.
    '''
    def get(self):
        '''
        Prints a hello message.
        '''
        return "Welcome to the secure shared server!"

class Login(Resource):
    '''
    Login API.
    '''
    def post(self):
        '''
            Logins a user using a signed statement and issues a session token.

            Expected response status codes:
            1) 200 - Login Successful
            2) 700 - Login Failed
        '''
        try:
            data = request.get_json()
            # Information coming from the client
            user_id = data['user-id']
            statement = data['statement']
            signed_statement = base64.b64decode(data['signed-statement'])

            session_token = user_manager.login_with_statement(statement, signed_statement, user_id)

            response = {
                'status': 200,
                'message': 'Login Successful',
                'session_token': session_token,
            }
        except Exception as err:
            print(traceback.print_exception(err, limit=3))
            response = {
                'status': 700,
                'message': 'Login Failed',
                'session_token': "INVALID",
            }
        
        return jsonify(response)

class Checkin(Resource):
    """
    Checkin API.
    """
    def post(self):
        '''
        Checks in a document.

        Expected response status codes:
        1) 200 - Document Successfully checked in
        2) 702 - Access denied checking in
        3) 700 - Other failures
        '''
        try:
            data = request.get_json()
            doc_id = data['document-id']
            security_flag = int(data['security-flag'])
            token = data['token']
            file_data = base64.b64decode(data['data'])

            user_id = user_manager.login_with_token(token)
            doc_manager.checkin(user_id, doc_id, file_data, security_flag)

            response = {
                'status': 200,
                'message': 'Document Successfully checked in'
            }
        except AccessDeniedError:
            response = {
                'status': 702,
                'message': 'Access denied checking in'
            }
        except Exception as err:
            print(traceback.print_exception(err, limit=3))
            response = {
                'status': 700,
                'message': 'Other failures'
            }

        return jsonify(response)

class Checkout(Resource):
    """
    Checkout API.
    """
    def post(self):
        """
        Checks out a document.

        Expected response status codes
        1) 200 - Document Successfully checked out
        2) 702 - Access denied checking out
        3) 703 - Check out failed due to broken integrity
        4) 704 - Check out failed since file not found on the server
        5) 700 - Other failures
        """
        try:
            data = request.get_json()
            token = data['token']
            doc_id = data['document-id']

            user_id = user_manager.login_with_token(token)

            file_data = doc_manager.checkout(user_id, doc_id)
            file = base64.b64encode(file_data).decode("utf-8")

            response = {
                'status': 200,
                'message': 'Document Successfully checked out',
                'file': file,
            }
        except AccessDeniedError:
            response = {
                'status': 702,
                'message': 'Access denied checking out',
                'file': 'Invalid',
            }
        except IntegrityCheckError:
            response = {
                'status': 703,
                'message': 'Check out failed due to broken integrity',
                'file': 'Invalid',
            }
        except NotFoundError:
            response = {
                'status': 704,
                'message': 'Check out failed since file not found on the server',
                'file': 'Invalid',
            }
        except Exception as err:
            print(traceback.print_exception(err, limit=3))

            response = {
                'status': 700,
                'message': 'Other failures',
                'file': 'Invalid',
            }

        return jsonify(response)

class Grant(Resource):
    '''
    Grant API.
    '''
    def post(self):
        """
            Grants a right to a user.

            Expected response status codes:
            1) 200 - Successfully granted access
            2) 702 - Access denied to grant access
            3) 700 - Other failures
        """
        try:
            data = request.get_json()
            token = data['token']
            doc_id = data['document-id']
            target_user_id = data["target-user-id"]
            access_level = int(data["access-level"])
            duration = int(data["duration"])
        
            user_id = user_manager.login_with_token(token)
            doc_manager.grant_access(user_id, doc_id, target_user_id, access_level, duration)

            response = {
                'status': 200,
                'message': 'Successfully granted access',
            }
        except AccessDeniedError:
            response = {
                'status': 702,
                'message': 'Access denied to grant access',
            }
        except Exception as err:
            print(traceback.print_exception(err, limit=3))

            response = {
                'status': 700,
                'message': 'Other failures',
            }

        return jsonify(response)

class Delete(Resource):
    """
    Delete API.    
    """
    def post(self):
        """
        Deletes a file.

        Expected response status codes:
        1) 200 - Successfully deleted the file
        2) 702 - Access denied deleting file
        3) 704 - Delete failed since file not found on the server
        4) 700 - Other failures
        """
        try:
            data = request.get_json()
            token = data['token']
            doc_id = data['document-id']

            user_id = user_manager.login_with_token(token)
            doc_manager.delete(user_id, doc_id)

            response = {
                'status': 200,
                'message': 'Successfully deleted the file',
            }
        except AccessDeniedError:
            response = {
                'status': 702,
                'message': 'Access denied deleting file',
            }
        except NotFoundError:
            response = {
                'status': 704,
                'message': 'Delete failed since file not found on the server',
            }
        except Exception as err:
            print(traceback.print_exception(err, limit=3))

            response = {
                'status': 700,
                'message': 'Other failures',
            }

        return jsonify(response)

class Logout(Resource):
    """
    Logout API.    
    """
    def post(self):
        """
        Logs out a user.

        Expected response status codes:
        1) 200 - Successfully logged out
        2) 700 - Failed to log out
        """

        try:
            data = request.get_json()
            token = data['token']

            user_manager.logout(token)

            response = {
                'status': 200,
                'message': 'Successfully logged out',
            }

        except Exception as err:
            print(traceback.print_exception(err, limit=3))
            
            response = {
                'status': 700,
                'message': 'Failed to log out',
            }

        return jsonify(response)

def main():
    """
    Entry-point for S3 Server Web API.
    """
    secure_shared_service = Flask(__name__)
    api = Api(secure_shared_service)

    api.add_resource(Welcome, '/')
    api.add_resource(Login, '/login')
    api.add_resource(Checkin, '/checkin')
    api.add_resource(Checkout, '/checkout')
    api.add_resource(Grant, '/grant')
    api.add_resource(Delete, '/delete')
    api.add_resource(Logout, '/logout')

    secure_shared_service.run(debug=True)

if __name__ == '__main__':
    main()
