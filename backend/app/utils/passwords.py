import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

def validate_password_strength(password: str, config: dict = None) -> tuple[bool, str]:
    if config is None: config = {}
    min_len = config.get('longitud_minima', 8)
    if len(password) < min_len: return False, f"Mínimo {min_len} caracteres"
    if config.get('requiere_mayuscula', True) and not any(c.isupper() for c in password): return False, "Falta mayúscula"
    if config.get('requiere_numero', True) and not any(c.isdigit() for c in password): return False, "Falta número"
    if config.get('requiere_especial', True) and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): return False, "Falta carácter especial"
    return True, "OK"