import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
import binascii

# ==========================================
# ส่วนที่ 1: การสร้างกุญแจ (Student ID Seeding)
# ==========================================
# ข้อมูลนักศึกษาสำหรับสร้าง Key และ Salt (เงื่อนไขป้องกัน AI)
student_id = "6611423233"
student_name = "wasawat kalasang"
seed_info = student_id + student_name

# สร้าง Key ขนาด 32 bytes (AES-256) จากการ Hash ชื่อ+รหัส
# ผลลัพธ์ที่ได้จะแตกต่างจากคนอื่นแน่นอน
encryption_key = hashlib.sha256(seed_info.encode()).digest()

# ==========================================
# ส่วนที่ 2: ระบบจัดการรหัสผ่าน (SHA-256 + Salt)
# ==========================================
def hash_nurse_password(password):
    # ใช้ชื่อนักศึกษาเป็น Salt เพื่อความปลอดภัย
    salt = student_name[:8] 
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed

# ==========================================
# ส่วนที่ 3: การเข้ารหัสข้อมูลอาหาร (AES-256 CBC)
# ==========================================
def encrypt_diet_order(order_text):
    cipher = AES.new(encryption_key, AES.MODE_CBC)
    # ทำ Padding ข้อมูลให้ครบ 16 bytes (ป้องกัน Error)
    padded_data = pad(order_text.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # เก็บค่า IV (Initialization Vector) ไว้สำหรับตอนถอดรหัส
    iv = binascii.hexlify(cipher.iv).decode()
    encrypted_msg = binascii.hexlify(ciphertext).decode()
    return iv, encrypted_msg

# ==========================================
# ส่วนที่ 4: การยืนยันตัวตน (ECC Digital Signature)
# ==========================================
# สร้างกุญแจคู่ (Private/Public Key) แบบ Ed25519
private_key = ECC.generate(curve='ed25519')
public_key = private_key.public_key()

def sign_by_nurse(message):
    signer = eddsa.new(private_key, 'rfc8032')
    signature = signer.sign(message.encode())
    return binascii.hexlify(signature).decode()

# ==========================================
# ส่วนทดสอบระบบ (Main Execution)
# ==========================================
if __name__ == "__main__":
    print(f"--- ระบบความปลอดภัยโดย: {student_name} ({student_id}) ---")
    
    # 1. ทดสอบ Hashing
    print(f"[+] Password Hash: {hash_nurse_password('SecurePass123')}")
    
    # 2. ทดสอบ Encryption
    order = "คนไข้เตียง 05: งดอาหารรสจัด และควบคุมน้ำตาล"
    iv, ct = encrypt_diet_order(order)
    print(f"[+] Encrypted Order (AES-256): {ct}")
    
    # 3. ทดสอบ Digital Signature
    sig = sign_by_nurse(order)
    print(f"[+] Digital Signature (ECC): {sig}")
    print("-" * 50)
