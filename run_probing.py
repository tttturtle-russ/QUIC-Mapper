from probing.client import create_client
import tls_args
def extract_words_by_line(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    words_by_line = []
    for line in lines:
        # 移除行尾的换行符，并按逗号分隔单词
        line_words = line.strip().split(', ')
        words_by_line.append(line_words)

    return words_by_line

    # 使用示例


file_path = 'probing/probes.txt'
words_by_line = extract_words_by_line(file_path)
output_path = 'probing/output.txt'

def main ():
    args = tls_args.parse_args(client_inference=False)
    local_ip, local_port = args.local_addr.split(':')
    local_port = int(local_port)

    dst_ip_add_str, dst_port_str = args.remote_addr.split(':')
    dst_port_int = int(dst_port_str)
    dst_addr = (dst_ip_add_str, dst_port_int)
    client = create_client(local_ip, local_port, dst_addr, args.timeout)
    output = []
    words_by_line = extract_words_by_line(file_path)
    with open(output_path, 'a', encoding='utf-8') as file:
        # file.seek(0)
        for line_words in words_by_line:
            client.reset()
            for word in line_words:
                # print(word)
                response = client.send_and_receive(word)
                file.write(f'"{word} / {response}",')
                # output.append(f'{word} / {response}')
                # print(f'"{word} / {response}",')
            file.write('\n')
            client.close()

main()