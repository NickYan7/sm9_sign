
import binascii
from math import ceil, floor, log
from .sm3 import sm3_kdf, sm3_hash

from random import SystemRandom

from . import optimized_field_elements as fq
from . import optimized_curve as ec
from . import optimized_pairing as ate

FAILURE = False
SUCCESS = True


def bitlen(n):
    """
    计算一个数的二进制形式有几位，比如 bitlen(128)=8，128的二进制数是8位
    floor 向下取整，log(n, 2)中2为底数
    :param n:
    :return:
    """
    return floor(log(n,2) + 1)

def i2sp(m, l):
    """
    %x 以十六进制形式输出
    zfill()在左侧填充l的2倍个0
    :param m: 必须是数字
    :param l:
    :return:
    """
    format_m = ('%x' % m).zfill(l*2).encode('utf-8')
    octets = [j for j in binascii.a2b_hex(format_m)] # a2b_hex() 返回十六进制字符串的二进制形式
    octets = octets[0:l] # 只取第一个值
    return ''.join(['%02x' %oc for oc in octets])

def fe2sp (fe):
    fe_str = ''.join (['%x' %c for c in fe.coeffs])
    if (len(fe_str) % 2) == 1:
        fe_str = '0' + fe_str
    return fe_str

def ec2sp (P):
    ec_str = ''.join([fe2sp(fe) for fe in P])
    return ec_str

def str2hexbytes (str_in):
    return [b for b in str_in.encode ('utf-8')]

def h2rf (i, z, n):
    l = 8 * ceil ((5*bitlen(n)) / 32)
    msg = i2sp(i,1).encode('utf-8')
    ha = sm3_kdf (msg+z, l)
    h = int (ha, 16)
    return (h % (n-1)) + 1

def setup (scheme):
    """
    准备模块。当接收到 sign 参数时，开始生成主公钥和随机数 s（即签名主私钥）
    :param scheme: 参数 scheme 接收签名 sign，密钥协商或加密(keyagreement/encrypt)
    :return: 返回签名主公钥 master_public_key 和随机数 s（即签名主私钥）
    """
    # 生成元 P1/P2
    P1 = ec.G2
    P2 = ec.G1

    rand_gen = SystemRandom()
    s = rand_gen.randrange (ec.curve_order) # 生成随机数 s，即签名主私钥

    if (scheme == 'sign'):
        Ppub = ec.multiply(P2, s)   # 返回的是签名主公钥
        g = ate.pairing(P1, Ppub)  # 计算群 GT 中的元素 g=e(P1, Ppub)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Ppub = ec.multiply(P1, s)
        g = ate.pairing(Ppub, P2)
    else:
        raise Exception('Invalid scheme')

    master_public_key = (P1, P2, Ppub, g)
    return (master_public_key, s)

def private_key_extract(scheme, master_public, master_secret, identity):
    """
    生成私钥 Da
    :param scheme:
    :param master_public: 主公钥
    :param master_secret: 主私钥
    :param identity: 用户的标识
    :return: 签名者的私钥 Da
    """
    P1 = master_public[0]
    P2 = master_public[1]

    user_id = sm3_hash(str2hexbytes(identity))
    m = h2rf (1, (user_id + '01').encode('utf-8'), ec.curve_order)
    m = master_secret + m
    if (m % ec.curve_order) == 0:
        return FAILURE
    m = master_secret * fq.prime_field_inv(m, ec.curve_order)

    if (scheme == 'sign'):
        Da = ec.multiply(P1, m)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Da = ec.multiply(P2, m)
    else:
        raise Exception('Invalid scheme')

    return Da

def public_key_extract(scheme, master_public, identity):
    """
    生成公钥
    :param scheme: 类型
    :param master_public: 主公钥
    :param identity: 标识
    :return:
    """
    P1, P2, Ppub, g = master_public

    user_id = sm3_hash(str2hexbytes(identity))
    #print(f"user_id ===== {user_id}")
    h1 = h2rf(1, (user_id + '01').encode('utf-8'), ec.curve_order)

    if (scheme == 'sign'):
        Q = ec.multiply(P2, h1)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Q = ec.multiply (P1, h1)
    else:
        raise Exception('Invalid scheme')

    Q = ec.add(Q, Ppub)

    return Q

# scheme = 'sign'
def sign(master_public, Da, msg):
    """
    数字签名部分
    :param master_public: 主公钥，由 KGC 在 setup() 时生成
    :param Da: 签名用户 A 的私钥
    :param msg: 待签名消息，用户输入
    :return: 返回 signature，类型 tuple
    """
    # 按照数字签名生成算法流程计算 g/w/h/l/S
    g = master_public[3]

    rand_gen = SystemRandom()
    x = rand_gen.randrange(ec.curve_order)
    print(f"[+] Random number r is {x}")
    w = g**x

    msg_hash = sm3_hash(str2hexbytes(msg))  # sm3 杂凑函数压缩消息
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf(2, z, ec.curve_order)  # 整数 h
    l = (x - h) % ec.curve_order    # 整数 l

    S = ec.multiply(Da, l)
    print(f"[+] First w is {w}")
    return (h, S)

def verify(master_public, identity, msg, signature):
    """
    验证签名部分
    :param master_public: A 生成的签名主公钥
    :param identity: A 的标识
    :param msg: 待验证消息
    :param signature: 数字签名 (h', S')
    :return: 返回成功 SUCCESS 或失败 FAILURE
    """

    (h, S) = signature

    if (h < 0) | (h >= ec.curve_order):
        # 首先判断 h' 的范围，若不在范围内则验证失败
        return FAILURE
    if ec.is_on_curve(S, ec.b2) == False:
        # 判断 S 是否在曲线上，若不在则验证失败
        return FAILURE

    Q = public_key_extract('sign', master_public, identity)

    # 依照 SM9 数字签名验证算法流程计算 g/u/t/w'/h2
    g = master_public[3]
    u = ate.pairing (S, Q)
    t = g**h
    wprime = u * t  # w' = u * t

    msg_hash = sm3_hash(str2hexbytes(msg))
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h2 = h2rf(2, z, ec.curve_order) # ec.curve_order 是循环群 G1 G2 GT 的阶，为大于 2**191 的素数

    print(f"[+] Second w is {wprime}")
    print(f"h2 ==> \033[32;1m{h2}\033[0m , compare it with h'...")

    if h != h2:
        return FAILURE
    return SUCCESS

# scheme = 'keyagreement'
def generate_ephemeral (master_public, identity):
    Q = public_key_extract ('keyagreement', master_public, identity)

    rand_gen = SystemRandom()
    x = rand_gen.randrange (ec.curve_order)
    R = ec.multiply (Q, x)

    return (x, R)

def generate_session_key (idA, idB, Ra, Rb, D, x, master_public, entity, l):
    P1, P2, Ppub, g = master_public

    if entity == 'A':
        R = Rb
    elif entity == 'B':
        R = Ra
    else:
        raise Exception('Invalid entity')

    g1 = ate.pairing (R, D)
    g2 = g**x
    g3 = g1**x

    if (entity == 'B'):
        (g1, g2) = (g2, g1)

    uidA = sm3_hash (str2hexbytes (idA))
    uidB = sm3_hash (str2hexbytes (idB))

    kdf_input = uidA + uidB
    kdf_input += ec2sp(Ra) + ec2sp (Rb)
    kdf_input += fe2sp(g1) + fe2sp(g2) + fe2sp(g3)

    sk = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return sk

# encrypt

def kem_encap (master_public, identity, l):
    P1, P2, Ppub, g = master_public

    Q = public_key_extract ('encrypt', master_public, identity)

    rand_gen = SystemRandom()
    x = rand_gen.randrange (ec.curve_order)

    C1 = ec.multiply (Q, x)
    t = g**x

    uid = sm3_hash (str2hexbytes (identity))
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return (k, C1)

def kem_decap (master_public, identity, D, C1, l):
    if ec.is_on_curve (C1, ec.b2) == False:
        return FAILURE

    t = ate.pairing (C1, D)

    uid = sm3_hash (str2hexbytes (identity))
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return k

def kem_dem_enc (master_public, identity, message, v):
    hex_msg = str2hexbytes (message)
    mbytes = len(hex_msg)
    mbits = mbytes * 8

    k, C1 = kem_encap (master_public, identity, mbits + v)
    k = str2hexbytes (k)
    k1 = k[:mbytes]
    k2 = k[mbytes:]

    C2 = []
    for i in range (mbytes):
        C2.append (hex_msg[i] ^ k1[i])

    hash_input = C2 + k2
    C3 = sm3_hash(hash_input)[:int(v/8)]

    return (C1, C2, C3)

def kem_dem_dec (master_public, identity, D, ct, v):
    C1, C2, C3 = ct

    mbytes = len(C2)
    l = mbytes*8 + v
    k = kem_decap (master_public, identity, D, C1, l)

    k = str2hexbytes (k)
    k1 = k[:mbytes]
    k2 = k[mbytes:]

    hash_input = C2 + k2
    C3prime = sm3_hash(hash_input)[:int(v/8)]

    if C3 != C3prime:
        return FAILURE

    pt = []
    for i in range (mbytes):
        pt.append (chr (C2[i] ^ k1[i]))

    message = ''.join(pt)

    return message
