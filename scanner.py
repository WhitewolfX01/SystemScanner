import subprocess
import shlex

def run_nmap(ip_address, output_file):
    command = f"nmap -A {ip_address} -oN {output_file}"
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        print("Nmap Scan Results:")
        print(result.stdout)
    except Exception as e:
        print(f"Error running Nmap: {e}")

def run_nikto(ip_address, output_file):
    command = f"nikto -h {ip_address} -o {output_file}"
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        print("Nikto Scan Results:")
        print(result.stdout)
    except Exception as e:
        print(f"Error running Nikto: {e}")

def run_test_py():
    command = "python3 test.py"
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        print("test.py Execution Results:")
        print(result.stdout)
    except Exception as e:
        print(f"Error running test.py: {e}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    output_file = "/home/kali/Desktop/scan.txt"

    run_nmap(target_ip, output_file)
    run_nikto(target_ip, output_file)
    run_test_py()

    print(f"Scan results and test.py execution results saved to {output_file}")
