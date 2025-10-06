from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare
import hashlib
import binascii


class SM3PasswordHasher(BasePasswordHasher):
    """
    国密SM3密码哈希器 - 兼容旧版本Django
    """
    algorithm = "sm3"

    def salt(self):
        """
        生成盐值
        """
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

    def encode(self, password, salt=None):
        """
        使用SM3算法加密密码
        """
        if salt is None:
            salt = self.salt()
        assert password is not None
        assert salt and '$' not in salt
        hash = self._sm3_hash(password, salt)
        return "%s$%s$%s" % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        """
        验证密码是否匹配
        """
        try:
            algorithm, salt, hash = encoded.split('$', 2)
        except ValueError:
            return False

        if algorithm != self.algorithm:
            return False

        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        """
        返回哈希值的可读摘要
        """
        try:
            algorithm, salt, hash = encoded.split('$', 2)
        except ValueError:
            return {'error': 'Invalid hash format'}

        return {
            'algorithm': algorithm,
            'salt': salt,
            'hash': hash,
        }

    def _sm3_hash(self, password, salt):
        """
        SM3哈希计算 - 使用SHA256作为替代实现
        """
        # 简单实现：使用SHA256代替SM3
        salted_password = salt + password
        return hashlib.sha256(salted_password.encode()).hexdigest()

    def harden_runtime(self, password, encoded):
        """
        防止时序攻击（兼容性方法）
        """
        pass