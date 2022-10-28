import bcrypt

def genHashedPwd(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verifyPwd(normal_password, hashed_password):
    return bcrypt.checkpw(normal_password.encode('utf-8'), hashed_password.encode('utf-8'))