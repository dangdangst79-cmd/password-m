import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_key(master_password: str) -> bytes:
    """
    사용자가 입력한 마스터 비밀번호를 기반으로 
    AES-256 암호화에 사용할 32바이트 크기의 단단한 '강철 열쇠'를 만듭니다.
    """
    # 💡 [핵심 수정] 입력받은 마스터 비밀번호를 반드시 명시적으로 utf-8 바이트로 변환합니다.
    if isinstance(master_password, str):
        master_password_bytes = master_password.encode('utf-8')
    else:
        master_password_bytes = master_password
        
    return hashlib.sha256(master_password_bytes).digest()

def encrypt_password(plain_text: str, master_password: str) -> str:
    """
    일반 비밀번호를 마스터 비밀번호로 암호화하여 알아볼 수 없는 외계어 문장으로 바꿉니다.
    """
    if not plain_text:
        return ""
        
    key = generate_key(master_password)
    cipher = AES.new(key, AES.MODE_CBC)
    
    # 일반 패스워드 텍스트도 utf-8 바이트로 안전하게 인코딩
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    
    combined = cipher.iv + encrypted_bytes
    return base64.b64encode(combined).decode('utf-8')

def decrypt_password(encrypted_text: str, master_password: str) -> str:
    """
    외계어로 변환되어 있던 암호문을 마스터 비밀번호를 이용해 원래 비밀번호로 되돌립니다.
    """
    if not encrypted_text:
        return ""
        
    try:
        key = generate_key(master_password)
        combined = base64.b64decode(encrypted_text.encode('utf-8'))
        
        iv = combined[:16]
        ciphertext = combined[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return "❌ [해독 실패] 마스터 비밀번호가 틀렸습니다!"