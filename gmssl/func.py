from random import choice

# ^ 表示按位异或
# 传入参数a和b是list迭代器，分别传给x和y，进行按位异或运算，最后顺序输出一个列表
xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))

# 0xffffffff是32位全为1的二进制数，| 表示按位或，<< 表示左移n位，& 表示按位与
# rotl(x, n) 实现了一个循环左移位，x为被移位数，n表示移几位，不超过32位，否则右移
rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))

put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]

padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]

unpadding = lambda data: data[:-data[-1]]

list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])

bytes_to_list = lambda data: [i for i in data]

random_hex = lambda x: ''.join([choice('0123456789abcdef') for _ in range(x)])
