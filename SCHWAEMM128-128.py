""""SPARKLE SCHWAEMM_128_128"""

from projectq import MainEngine
from projectq.ops import H, CNOT, Measure, Toffoli, X, All, Swap
from projectq.backends import CircuitDrawer, ResourceCounter, CommandPrinter, ClassicalSimulator
from projectq.meta import Loop, Compute, Uncompute, Control

def RC_XOR(eng, rc, qubits, n):
    for i in range(n):
        if((rc >> i) & 1):
            X | qubits[i]

def concat_NK(eng, key, state, n):
    for i in range(n):
        CNOT | (key[i], state[32*(3-int(i/32)) + i%32])

def trunc(eng, s, c, n):
    for i in range(n):
        CNOT | (s[255 - i], c[31 - i]) # c[0] ^= x0

def SCHWAEMM_128_128(eng, M_value, Key, Nonce, Auth_value, len):
    # carry bit
    carry = eng.allocate_qureg(4)

    # PT
    M = eng.allocate_qureg(len)
    C = eng.allocate_qureg(len)
    if(resource_check != 1):
        RC_XOR(eng, M_value, M, len)
        RC_XOR(eng, M_value, C, len)


    # AD
    A = eng.allocate_qureg(len)
    if(resource_check != 1):
        RC_XOR(eng, Auth_value, A, len)

    S = eng.allocate_qureg(256)
    K = eng.allocate_qureg(128)
    N = eng.allocate_qureg(128)
    if(resource_check != 1):
        RC_XOR(eng, Key, K, 128)
    if (resource_check != 1):
        RC_XOR(eng, Nonce, N, 128)

    # N || K
    concat_NK(eng, K, S[:128], 128)
    concat_NK(eng, N, S[128:256], 128)

    A_last = []
    M_last = []

    for i in range(len):
      A_last.append(A[i])
      M_last.append(M[i])

    SPARKLE_256(eng, S, carry, 10)

    const = eng.allocate_qureg(3)
    X | const[2] # 0100
    for i in range(3):
        CNOT | (const[2 - i], S[26 - i]) # y[3] ^= CONSTA
    p1(eng, S, A_last, carry)

    ## SL ^ SR
    for i in range(32):
        CNOT | (S[127 - i], S[255 - i])
        CNOT | (S[95 - i], S[223 - i])
        CNOT | (S[63 - i], S[191 - i])
        CNOT | (S[31 - i], S[159 - i])

    SPARKLE_256(eng, S, carry, 10)
    trunc(eng, S, C, len)

    X | const[1] # 0110
    for i in range(3):
        CNOT | (const[2 - i], S[26 - i]) # y[3] ^= CONSTM

    p1(eng, S, M_last, carry)

    ## SL ^ SR
    for i in range(32):
        CNOT | (S[127 - i], S[255 - i])
        CNOT | (S[95 - i], S[223 - i])
        CNOT | (S[63 - i], S[191 - i])
        CNOT | (S[31 - i], S[159 - i])

    SPARKLE_256(eng, S, carry, 10)
    result = eng.allocate_qureg(128+len)

    for i in range(127, -1, -1):
        CNOT | (K[32*(3-int(i/32)) + i%32], S[i]) # SR ^= K
        CNOT | (S[i], result[i])

    for i in range(len-1, -1, -1):
        CNOT | (C[i], result[128+i])

    if(resource_check != 1):
        All(Measure) | result


def FeistelSwap(eng, s):
    for i in range(32):
        Swap | (s[191-i], s[255-i]) #x0 <-> x1
        Swap | (s[223-i], s[159-i]) #y0 <-> y1
    #
    for i in range(32):
        CNOT | (s[255-i], s[191-i]) # x0 ^= x1
        CNOT | (s[223-i], s[159-i]) # y0 ^= y1

def p1(eng, s, d, carry):
    if(resource_check != 1):
        FeistelSwap(eng, s)

    for i in range(32):
        CNOT | (d[31 - i], s[255 - i]) # x0 ^= AM[0]

    X | (s[199])

def SPARKLE_256(eng, x, carry, n):
    c = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]  # c0~c7

    x0 = []
    x1 = []
    x2 = []
    x3 = []

    y0 = []
    y1 = []
    y2 = []
    y3 = []

    for i in range(32):
        y3.append(x[i])
        x3.append(x[i + 32])
        y2.append(x[i + 64])
        x2.append(x[i + 96])
        y1.append(x[i + 128])
        x1.append(x[i + 160])
        y0.append(x[i + 192])
        x0.append(x[i + 224])

    for i in range(n):
        RC_XOR(eng, c[i%8], y0, 32)  # y[0] = y[0] ^ c[i]
        RC_XOR(eng, i, y1, 32)  # y[1] = y[1] ^ s

        # for(i=0; i<3; i++){ xi, yi = Aci(xi, yi) }
        x0, y0 = Alzette(eng, x0, y0, c[0], carry[0])
        x1, y1 = Alzette(eng, x1, y1, c[1], carry[1])
        x2, y2 = Alzette(eng, x2, y2, c[2], carry[2])
        x3, y3 = Alzette(eng, x3, y3, c[3], carry[3])

        L4(eng, x0, x1, x2, x3, y0, y1, y2, y3)

def XOR(eng, a, b, len):
    for i in range(len):
        CNOT | (a[i], b[i]) # b[i] = b[i] xor a[i]

def Swap_(eng, a, b):
    for i in range(32):
        Swap | (a[i], b[i])

def Alzette(eng, x, y, c, carry):
    # y>>>31
    new_y = []
    for i in range(32):
        new_y.append(y[(31+i) % 32])
    CDKM(eng, new_y, x, carry, 32) # x = x+y>>>31

    # x>>>24
    new_x = []
    for i in range(32):
        new_x.append(x[(24+i) % 32])
    # y=y^x>>>24
    for i in range(32):
        CNOT | (new_x[i], y[i])

    # x = x^c
    RC_XOR(eng, c, x, 32)

    # y>>>17
    new_y = []
    for i in range(32):
        new_y.append(y[(17 + i) % 32])
    CDKM(eng, new_y, x, carry, 32) # x = x+y>>>17

    # x>>>17
    new_x = []
    for i in range(32):
        new_x.append(x[(17 + i) % 32])

    for i in range(32):
        CNOT | (new_x[i], y[i])

    # x = x^c
    RC_XOR(eng, c, x, 32)

    CDKM(eng, y, x, carry, 32) # x = x+y>>>0

    # x>>>31
    new_x = []
    for i in range(32):
        new_x.append(x[(31 + i) % 32])

    # y=y^x>>>31
    for i in range(32):
        CNOT | (new_x[i], y[i])

    # x = x^c
    RC_XOR(eng, c, x, 32)

    # y>>>24
    new_y = []
    for i in range(32):
        new_y.append(y[(24 + i) % 32])
    CDKM(eng, new_y, x, carry, 32) # x = x+y>>>24

    # x>>>16
    new_x = []
    for i in range(32):
        new_x.append(x[(16 + i) % 32])
    # y=y^(x>>>16)
    for i in range(32):
        CNOT | (new_x[i], y[i])

    # x = x^c
    RC_XOR(eng, c, x, 32)

    return x, y

def L4(eng, x0, x1, x2, x3, y0, y1, y2, y3):
    # tx 연산 먼저
    with Compute(eng):
        XOR(eng, x1, x0, 32) # x0 = x0 ^ x1
        XOR(eng, x0[0:16], x0[16:32], 16) # x0(L) = x0(L) ^ x0(R)
    XOR(eng, x0[16:32], y2[0:16], 16) # y2 = y2 ^ tx
    XOR(eng, x0[0:16], y2[16:32], 16) # y2 = y2 ^ tx
    XOR(eng, y0, y2, 32) # y2 = y2 ^ y0

    XOR(eng, x0[16:32], y3[0:16], 16)  # y3 = y3 ^ tx
    XOR(eng, x0[0:16], y3[16:32], 16)  # y3 = y3 ^ tx
    XOR(eng, y1, y3, 32) # y3 = y3 ^ y1

    Uncompute(eng)

    with Compute(eng):
        XOR(eng, y1, y0, 32) # y0 = y0 ^ y1
        XOR(eng, y0[0:16], y0[16:32], 16) # y0(R) = y0(R) || y0(R) ^ y0(L)
    XOR(eng, y0[16:32], x2[0:16], 16)  # x2 = x2 ^ ty
    XOR(eng, y0[0:16], x2[16:32], 16)  # x2 = x2 ^ ty
    XOR(eng, x0, x2, 32) # x2 = x2 ^ x0

    XOR(eng, y0[16:32], x3[0:16], 16)  # x3 = x3 ^ ty
    XOR(eng, y0[0:16], x3[16:32], 16)  # x3 = x3 ^ ty
    XOR(eng, x1, x3, 32) # x3 = x3 ^ x1

    Uncompute(eng)

    if(resource_check != 1):
        Swap_(eng, x0, x2)
        Swap_(eng, x1, x3)
        Swap_(eng, y0, y2)
        Swap_(eng, y1, y3)

        Swap_(eng, x0, x1)
        Swap_(eng, y0, y1)

def XOR_32(eng, a, b):
    for i in range(32):
        CNOT | (a[i], b[i]) # b[i] = b[i]^a[i]

# quantum adder
def CDKM(eng, a, b, c, n):
    for i in range(n - 2):
        CNOT | (a[i + 1], b[i + 1])

    CNOT | (a[1], c)
    Toffoli | (a[0], b[0], c)
    CNOT | (a[2], a[1])
    Toffoli | (c, b[1], a[1])
    CNOT | (a[3], a[2])

    for i in range(n - 5):
        Toffoli | (a[i + 1], b[i + 2], a[i + 2])
        CNOT | (a[i + 4], a[i + 3])

    Toffoli | (a[n - 4], b[n - 3], a[n - 3])
    CNOT | (a[n - 2], b[n - 1])
    CNOT | (a[n - 1], b[n - 1])
    Toffoli | (a[n - 3], b[n - 2], b[n - 1])

    for i in range(n - 3):
        X | b[i + 1]

    CNOT | (c, b[1])

    for i in range(n - 3):
        CNOT | (a[i + 1], b[i + 2])

    Toffoli | (a[n - 4], b[n - 3], a[n - 3])

    for i in range(n - 5):
        Toffoli | (a[n - 5 - i], b[n - 4 - i], a[n - 4 - i])
        CNOT | (a[n - 2 - i], a[n - 3 - i])
        X | (b[n - 3 - i])

    Toffoli | (c, b[1], a[1])
    CNOT | (a[3], a[2])
    X | b[2]
    Toffoli | (a[0], b[0], c)
    CNOT | (a[2], a[1])
    X | b[1]
    CNOT | (a[1], c)

    for i in range(n-1):
        CNOT | (a[i], b[i])

global resource_check

resource_check = 0
Resource = ClassicalSimulator()
eng = MainEngine(Resource)
SCHWAEMM_128_128(eng, 0x03020100, 0x0F0E0D0C0B0A09080706050403020100, 0x0F0E0D0C0B0A09080706050403020100, 0x03020100, 32)
eng.flush()

resource_check = 1
Resource = ResourceCounter()
eng = MainEngine(Resource)
SCHWAEMM_128_128(eng, 0x03020100, 0x0F0E0D0C0B0A09080706050403020100, 0x0F0E0D0C0B0A09080706050403020100, 0x03020100, 32)
print(Resource)
eng.flush()