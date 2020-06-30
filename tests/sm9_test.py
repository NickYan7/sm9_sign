
import os, sys
import time

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
print(base_dir)

from gmssl import sm9


if __name__ == '__main__':

    # identity 必须是 str 类型
    print("=================== SM9 test sign and verify ===================")
    idA = str(input("[*] Please input user A's identity: "))
    #idB = 'b'

    # 生成签名主公钥和签名主私钥
    master_public, master_secret = sm9.setup('sign')
    print("========================== master key ==========================")
    print(f"[+] The master public key has been generated:\n\033[32;1m{master_public[2]}\033[0m")
    print(f"[+] The master secret key has been generated:\n\033[32;1m{master_secret}\033[0m")
    print("================================================================")


    # 生成签名者的私钥
    Da = sm9.private_key_extract('sign', master_public, master_secret, idA)

    # msg 必须是 str 类型
    while True:
        flag = int(input("""
========================= select mode ===========================
[1] Sign the message which is input.
[2] Sign files.
[*] Please select sign mode:"""))
        if flag == 1:
            message = str(input("\n[*] Please input the message to be signed: "))
            break

        if flag == 2:
            message_path = str(input("\n[*] Please input the absolute path of the file to be signed: "))
            try:
                with open(message_path, "rb") as f:
                    message = str(f.read())
                    break
            except FileNotFoundError:
                print("\033[31;1m[-] file is not exist.\033[0m")
                continue
        else:
            print("\033[31;1m[-] Invalid input!\033[0m")
            continue

    start_time = time.time()
    signature = sm9.sign(master_public, Da, message)    # signature 的数据类型是一个元组
    sign_time = time.time()
    print(f"\033[30;1m[+] It spends {sign_time - start_time}s to sign.\033[0m")
    print("\n[+] (h, S) has already generated.")

    print(f"[+] Now print (h, S) which is a tuple:\n{signature}")

    print("\n[*] Now verify the signature...")
    # assert(断言) 用于判断表达式，在表达式条件为 False 时触发异常
    if not sm9.verify(master_public, idA, message, signature):
        print("[-] Verify Failed...")
        exit()

    verify_time = time.time()
    print("[+] Verify success!")
    print(f"\033[30;1m[+] It spends {verify_time - sign_time}s to verify.\033[0m")
