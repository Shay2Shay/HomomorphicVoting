import requests
p = None

# =================== DHKE ===================
# p = requests.post(
#     'http://127.0.0.1:8000/dhke',
#     {
#         'email': 'animesh.s21@iiits.in',
#         'pubKeyDHKE': 2,
#         'n': 23,
#         'g': 15
#     }
# )
# ============================================

# =================== AES ===================
# p = requests.post(
#     'http://127.0.0.1:8000/login',
#     {
#         'email': 'animesh.s21@iiits.in',
#         'rsa1024pubkey': 2
#     }
# )
# ===========================================
print(p.text)