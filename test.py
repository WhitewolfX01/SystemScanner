import re
import subprocess
import shlex

def parse_nmap_results(file_path):
    with open(file_path, 'r') as file:
        nmap_results = file.read()

    # Define keywords that indicate vulnerabilities or weaknesses for Nmap
    vulnerability_keywords = [
        'open', 'vulnerable', 'weak', 'insecure', 'misconfigured', 'exploitable', 'unprotected',
        'outdated', 'missing x-frame-options', 'missing x-content-type-options',
        'uncommon header \'tcn\'', 'apache mod_negotiation enabled', 'http trace method active',
        'directory indexing', 'php reveals potentially sensitive information',
        'phpmyadmin is for managing mysql databases', 'server may leak inodes via etags',
        'exposed wordpress configuration', 'not present', 'leak', 'leak'
    ]

    # Extract relevant information based on keywords
    filtered_results = []
    for line in nmap_results.split('\n'):
        for keyword in vulnerability_keywords:
            if keyword in line.lower():
                service_match = re.search(r'\d+\/(\w+)', line)
                if service_match:
                    service_name = service_match.group(1)
                    result = f"{service_name}: {line.strip()}"
                    filtered_results.append(result)
                    break

    return filtered_results

def parse_nikto_results(file_path):
    with open(file_path, 'r') as file:
        nikto_results = file.read()

    # Define keywords that indicate vulnerabilities or weaknesses for Nikto
    nikto_vulnerability_keywords = [
        'X-Frame-Options header is not present.',
        'Server may leak inodes via ETags',
        'Apache appears to be outdated',
    ]

    # Extract relevant information based on precise keywords for Nikto
    filtered_results = []
    for line in nikto_results.split('\n'):
        for keyword in nikto_vulnerability_keywords:
            if keyword.lower() in line.lower():
                # Extract vulnerability type and its solution
                vulnerability_type_match = re.search(r'\+ (.+?):', line)
                if vulnerability_type_match:
                    vulnerability_type = vulnerability_type_match.group(1).strip()
                    result = f"{vulnerability_type}: {line.strip()}"
                    filtered_results.append(result)
                    break

    return filtered_results

def save_filtered_results(filtered_results, output_file_path):
    with open(output_file_path, 'a') as output_file:  # Use 'a' to append instead of 'w' to write
        for result in filtered_results:
            output_file.write(result + '\n')

def run_main_py():
    command = "python3 main.py"
    try:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True)
        print("main.py Execution Results:")
        print(result.stdout)
    except Exception as e:
        print(f"Error running test.py: {e}")

if __name__ == "__main__":
    nmap_input_file_path = '/scan.txt'  # Replace with your actual Nmap file path
    nikto_input_file_path = 'scan.txt'  # Replace with your actual Nikto file path
    output_file_path = '/results.txt'  # Replace with your desired output file path

    nmap_filtered_results = parse_nmap_results(nmap_input_file_path)
    nikto_filtered_results = parse_nikto_results(nikto_input_file_path)

    combined_results = nmap_filtered_results + nikto_filtered_results
    save_filtered_results(combined_results, output_file_path)

    print(f"Filtered results saved to {output_file_path}")

    run_main_py()
