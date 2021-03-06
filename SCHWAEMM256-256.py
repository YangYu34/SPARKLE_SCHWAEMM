""""SPARKLE SCHWAEMM_256_256"""

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
        CNOT | (key[i], state[32*(int(n/32)-1-int(i/32)) + i%32])

def trunc(eng, s, c, n):
    for i in range(n):
        CNOT | (s[511 - i], c[31 - i]) # c[0] ^= x0


def SCHWAEMM_256_256(eng, M_value, Key, Nonce, Auth_value, len):
    # carry bit
    carry = eng.allocate_qureg(8)

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

    S = eng.allocate_qureg(512)
    K = eng.allocate_qureg(256)
    N = eng.allocate_qureg(256)
    if(resource_check != 1):
        RC_XOR(eng, Key, K, 256)
    if (resource_check != 1):
        RC_XOR(eng, Nonce, N, 256)

    # N || K
    concat_NK(eng, K, S[:256], 256)
    concat_NK(eng, N, S[256:512], 256)

    A_last = []
    M_last = []

    for i in range(len):
      A_last.append(A[i])
      M_last.append(M[i])
    
    SPARKLE_512(eng, S, carry, 12)

    ## AD 계산
    # y[7] ^= CONSTA, 1 0000 (0x10)
    X | S[28]

    p1(eng, S, A_last, carry)

    ## SL ^ SR
    for i in range(32):
        CNOT | (S[255 - i], S[511 - i])
        CNOT | (S[223 - i], S[479 - i])
        CNOT | (S[191 - i], S[447 - i])
        CNOT | (S[159 - i], S[415 - i])
        CNOT | (S[127 - i], S[383 - i])
        CNOT | (S[95 - i], S[351 - i])
        CNOT | (S[63 - i], S[319 - i])
        CNOT | (S[31 - i], S[287 - i])

    SPARKLE_512(eng, S, carry, 12)

    trunc(eng, S, C, len)

    # y[7] ^= CONSTM, 1 0010 (0x12)
    X | S[28]
    X | S[25]

    p1(eng, S, M_last, carry)

    ## SL ^ SR
    for i in range(32):
        CNOT | (S[255 - i], S[511 - i])
        CNOT | (S[223 - i], S[479 - i])
        CNOT | (S[191 - i], S[447 - i])
        CNOT | (S[159 - i], S[415 - i])
        CNOT | (S[127 - i], S[383 - i])
        CNOT | (S[95 - i], S[351 - i])
        CNOT | (S[63 - i], S[319 - i])
        CNOT | (S[31 - i], S[287 - i])

    
    SPARKLE_512(eng, S, carry, 12)

    
    for i in range(255, -1, -1):
        CNOT | (K[32*(7-int(i/32)) + i%32], S[i])
    
    if(resource_check != 1):
        All(Measure) | C
        All(Measure) | S
        C = Concat(eng, S[:256], C)  # C||T

    


def FeistelSwap(eng, s):
    for i in range(32):
        Swap | (s[511-i], s[383-i]) #x2 <-> x0
        Swap | (s[479-i], s[351-i]) #y2 <-> y0
        Swap | (s[447-i], s[319-i]) #x3 <-> x1
        Swap | (s[415-i], s[287-i]) #y3 <-> y1
    #
    for i in range(32):
        CNOT | (s[511 - i], s[383 - i])  # x2 ^= x0
        CNOT | (s[479 - i], s[351 - i])  # y2 ^= y0
        CNOT | (s[447 - i], s[319 - i])  # x3 ^= x1
        CNOT | (s[415 - i], s[287 - i])  # y3 ^= y1

def p1(eng, s, d, carry):

    if(resource_check != 1):
        FeistelSwap(eng, s)

    for i in range(32):
        CNOT | (d[31 - i], s[511 - i]) # x0 ^= AM[0]
    X | (s[455])


def SPARKLE_512(eng, x, carry, n):
    c = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D]  # c0~c7

    x0 = []
    x1 = []
    x2 = []
    x3 = []
    x4 = []
    x5 = []
    x6 = []
    x7 = []

    y0 = []
    y1 = []
    y2 = []
    y3 = []
    y4 = []
    y5 = []
    y6 = []
    y7 = []

    for i in range(32):
        y7.append(x[i])
        x7.append(x[i + 32])
        y6.append(x[i + 64])
        x6.append(x[i + 96])
        y5.append(x[i + 128])
        x5.append(x[i + 160])
        y4.append(x[i + 192])
        x4.append(x[i + 224])
        y3.append(x[i + 256])
        x3.append(x[i + 288])
        y2.append(x[i + 320])
        x2.append(x[i + 352])
        y1.append(x[i + 384])
        x1.append(x[i + 416])
        y0.append(x[i + 448])
        x0.append(x[i + 480])


    for i in range(n):
        RC_XOR(eng, c[i%8], y0, 32)  # y[0] = y[0] ^ c[i]
        RC_XOR(eng, i, y1, 32)  # y[1] = y[1] ^ s

        # for(i=0; i<3; i++){ xi, yi = Aci(xi, yi) }
        x0, y0 = Alzette(eng, x0, y0, c[0], carry[0])
        x1, y1 = Alzette(eng, x1, y1, c[1], carry[1])
        x2, y2 = Alzette(eng, x2, y2, c[2], carry[2])
        x3, y3 = Alzette(eng, x3, y3, c[3], carry[3])
        x4, y4 = Alzette(eng, x4, y4, c[4], carry[4])
        x5, y5 = Alzette(eng, x5, y5, c[5], carry[5])
        x6, y6 = Alzette(eng, x6, y6, c[6], carry[6])
        x7, y7 = Alzette(eng, x7, y7, c[7], carry[7])

        L8(eng, x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, y6, y7)

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

def L8(eng, x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, y6, y7):
    
    with Compute(eng):
        XOR(eng, x1, x0, 32) # x0 = x0 ^ x1
        XOR(eng, x2, x0, 32) # x0 = x0 ^ x2
        XOR(eng, x3, x0, 32)  # x0 = x0 ^ x3
        XOR(eng, x0[0:16], x0[16:32], 16) # x0(L) = x0(L) ^ x0(R), x0 ^ (x0 <<16) <<<16

    XOR(eng, x0[16:32], y4[0:16], 16)  # y4 ^= tx
    XOR(eng, x0[0:16], y4[16:32], 16)  # y4 ^= tx
    XOR(eng, y0, y4, 32) # y4 = y4 ^ y0

    XOR(eng, x0[16:32], y5[0:16], 16)  # y5 ^= tx
    XOR(eng, x0[0:16], y5[16:32], 16)  # y5 ^= tx
    XOR(eng, y1, y5, 32)  # y5 = y5 ^ y1

    XOR(eng, x0[16:32], y6[0:16], 16)  # y6 ^= tx
    XOR(eng, x0[0:16], y6[16:32], 16)  # y6 ^= tx
    XOR(eng, y2, y6, 32)  # y6 = y6 ^ y2

    XOR(eng, x0[16:32], y7[0:16], 16)  # y7 ^= tx
    XOR(eng, x0[0:16], y7[16:32], 16)  # y7 ^= tx
    XOR(eng, y3, y7, 32)  # y7 ^= y3

    Uncompute(eng) # reverse

    with Compute(eng):
        XOR(eng, y1, y0, 32) # y0 = y0 ^ y1
        XOR(eng, y2, y0, 32)  # y0 = y0 ^ y2
        XOR(eng, y3, y0, 32)  # y0 = y0 ^ y3
        XOR(eng, y0[0:16], y0[16:32], 16) # y0(R) = y0(R) || y0(R) ^ y0(L)

    XOR(eng, y0[16:32], x4[0:16], 16)  # x4 ^= ty
    XOR(eng, y0[0:16], x4[16:32], 16)  # x4 ^= ty
    XOR(eng, x0, x4, 32) # x4 ^= x0

    XOR(eng, y0[16:32], x5[0:16], 16)  # x5 ^= ty
    XOR(eng, y0[0:16], x5[16:32], 16)  # x5 ^= ty
    XOR(eng, x1, x5, 32)  # x5 ^= x1

    XOR(eng, y0[16:32], x6[0:16], 16)  # x6 ^= ty
    XOR(eng, y0[0:16], x6[16:32], 16)  # x6 ^= ty
    XOR(eng, x2, x6, 32)  # x6 ^= x2

    XOR(eng, y0[16:32], x7[0:16], 16)  # x7 ^= ty
    XOR(eng, y0[0:16], x7[16:32], 16)  # x7 ^= ty
    XOR(eng, x3, x7, 32)  # x7 ^= x3

    Uncompute(eng)

    if(resource_check != 1):
        Swap_(eng, x0, x4)
        Swap_(eng, x1, x5)
        Swap_(eng, x2, x6)
        Swap_(eng, x3, x7)
        Swap_(eng, y0, y4)
        Swap_(eng, y1, y5)
        Swap_(eng, y2, y6)
        Swap_(eng, y3, y7)

        Swap_(eng, x0, x1)
        Swap_(eng, y0, y1)
        Swap_(eng, x1, x2)
        Swap_(eng, y1, y2)
        Swap_(eng, x2, x3)
        Swap_(eng, y2, y3)

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
        
# c = b||a
def Concat(eng, a, b):
    c = []
    for i in range(len(a)):
        c.append(a[i])
    for i in range(len(b)):
        c.append(b[i])
    return c

global resource_check

resource_check = 0
Resource = ClassicalSimulator()
eng = MainEngine(Resource)
SCHWAEMM_256_256(eng, 0x03020100, 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100, 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100, 0x03020100, 32)
eng.flush()

resource_check = 1
Resource = ResourceCounter()
eng = MainEngine(Resource)
SCHWAEMM_256_256(eng, 0x03020100, 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100, 0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100,0x03020100, 32)
print(Resource)
eng.flush()
