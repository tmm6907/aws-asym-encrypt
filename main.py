from typing import Tuple
import boto3
import os
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class Response:
    def __init__(self, response) -> None:
        self.response = response
    def __str__(self) -> str:
        return self.response['Plaintext'].decode()

class AWSAsymmetricEncryption:
    def __init__(self, client, key_id, algorithm="RSAES_OAEP_SHA_256") -> None:
        self.client = client
        self.key_id = key_id
        self.algorithm = algorithm
    
    @classmethod
    def default(cls) -> "AWSAsymmetricEncryption":
        client = boto3.client("kms")
        return AWSAsymmetricEncryption(client, KEY_ID)
    
    def __get_public_key(self) -> bytes:
        der_public_key = self.client.get_public_key(KeyId=self.key_id)['PublicKey']
        public_key_pem = serialization.load_der_public_key(der_public_key)
        
        # Serialize the public key back into PEM format
        pem_public_key = public_key_pem.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
        return pem_public_key
    
    def encrypt(self, text: str, salt= None) -> Tuple[bytes, str]:
        if not salt:
            salt = secrets.token_urlsafe(16)
        text = (salt + text).encode()
        public_key_pem = self.__get_public_key()
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
        ciphertext = public_key.encrypt(
            text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext, salt
    
    def decrypt(self, cipher_text: bytes) -> bytes:
        res = Response(self.client.decrypt(
            KeyId=KEY_ID,
            CiphertextBlob=cipher_text,
            EncryptionAlgorithm=self.algorithm
        ))
        return str(res)
def add_row(db, ssn, dob, salt):
    db.append({
        "ssn": ssn,
        "dob": dob,
        "salt": salt,
    })
    return db
    
def main():
    db = []
    input1 = [
        "184884298",
        "706733051",
        "498196629",
        "754408051",
        "249188700",
        "597104379",
        "134812530",
        "017807177",
        "461143434",
        "508099013",
    ]
    
    input2 = [
        "20040902",
        "19210722",
        "19500318",
        "19660825",
        "20190925",
        "19440927",
        "19710625",
        "19300928",
        "20000118",
        "19151218",
    ]
    
    crypto = AWSAsymmetricEncryption.default()
    data = zip(input1, input2)
    for ssn, dob in data:
        enc_ssn, salt = crypto.encrypt(ssn)
        enc_dob, _ = crypto.encrypt(dob, salt)
        db = add_row(db, enc_ssn, enc_dob, salt)
        
    print("Database after encryption:", db)
    dec_db = []
    for row in db:
        enc_ssn = row["ssn"]
        enc_dob = row["dob"]
        salt = row["salt"]
        salt_len = len(salt)
        ssn_data = crypto.decrypt(enc_ssn)
        dob_data = crypto.decrypt(enc_dob)
        ssn = ssn_data[salt_len:]
        dob = dob_data[salt_len:]
        dec_db = add_row(dec_db, ssn, dob, salt)
    
    print("Database after decryption:", dec_db)
    
if __name__ == "__main__":
    main()
