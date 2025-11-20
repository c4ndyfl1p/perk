from Crypto.Random import get_random_bytes

a = [[None, None]]
n = 3
# c = [None * n]
d = [None] * n
e = [b'0'] * n
# print(c)
print(d)
print(e)
print(type(a))
# print(type(b))


testbytes = b'123456789'
print(type(testbytes))
print(len(testbytes))

key = get_random_bytes(16)
print(key)

print(128//8)

print(testbytes[0:3])
print(testbytes[3:])