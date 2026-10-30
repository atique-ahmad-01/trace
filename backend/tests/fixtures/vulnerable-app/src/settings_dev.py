"""Intentionally insecure test fixture: hard-coded deploy key.

The key below is random bytes in PEM framing. It is NOT a real or usable key;
it exists only so secret scanners (Gitleaks) have something to detect.
"""

DEPLOY_KEY = """-----BEGIN RSA PRIVATE KEY-----
3U5RpuPEVOn8ZR83oNspHtuk7jRkjaZkE9MTqd2dnABTQNSa5+wJAJhM7asJLWnG
sGeWmhk2J8z6DaSVLSh1Ful2sl3GaeKrwCE7FY6js7iBBhVf+YsE4x10P7S7VMqG
PnG/r7WUVppX4kcA7nPeLa1EkFQB2z+GWEBaTaKr28IiiAYsy/Mj2sQ7j9PkXz2D
4iB3FJ5KkNGIQUJHC99pff58PWw69EcF4jFCDpL9P4tAI7QdLEx5xCY9r+6y/i6n
q07vII13h7ZwL3jiJs7ozZpcnWW0XTEI4XhyOkDSaiXf4/GcKiNbnUl8VmbOogVh
-----END RSA PRIVATE KEY-----"""
