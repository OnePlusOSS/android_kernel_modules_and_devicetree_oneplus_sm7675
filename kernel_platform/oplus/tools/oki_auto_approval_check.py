import shutil
import os
import subprocess
import filecmp
import difflib

def enter_directory(dir_name):
    if os.path.exists(dir_name) and os.path.isdir(dir_name):
        os.chdir(dir_name)
        print("Entered the directory: {}".format(dir_name))
    else:
        print("The directory {} does not exist.".format(dir_name))

def is_remote_exist(remote_name):
    cmd = ['git', 'remote']
    output = subprocess.check_output(cmd).decode().strip().split('\n')
    return remote_name in output

def get_gerrit_username():
    cmd = ['git', 'config', '--get', 'user.name']
    username = subprocess.check_output(cmd).decode().strip()
    return username

def add_remote(username,remote_name):
    if is_remote_exist(remote_name):
        print('Remote {} already exists. Operation aborted.'.format(remote_name))
        return
    cmd = [
        'git', 'remote', 'add', remote_name,
        'ssh://{}@gerrit_url:29418/kernel/common'.format(username)
    ]
    output = subprocess.check_output(cmd).decode().strip()
    print('Command executed successfully. Output:', output)

def git_fetch(remote_name):
    cmd = ['git', 'fetch', remote_name, '-a']
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())
        process.poll()
        print("Git fetch command executed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error executing git fetch command.")
        print("Return code:", e.returncode)
        print("Output:")
        print(e.output)

def get_latest_commit_id():
    cmd = ["git", "log", "-1", "--format=%H"]

    try:
        commit_id = subprocess.check_output(cmd).decode().strip()
        print("Latest commit id: {}".format(commit_id))
        return commit_id
    except subprocess.CalledProcessError as e:
        print("Error executing git log command.")
        print("Return code:", e.returncode)
        print("Output:")
        print(e.output)
        return None


def get_git_log_output(commit_id):
    cmd = ['git', 'log', '-1', commit_id]

    git_log_output = subprocess.check_output(cmd).decode()
    print("\n")
    print(git_log_output)
    return git_log_output


def git_show_filtered(commit_id, output_filename):
    cmd = ['git', 'show', commit_id]
    git_output = subprocess.check_output(cmd).decode()

    # Filter the output results, retain rows starting with "+" or "-", and remove blank rows starting with "+" and "-"
    filtered_output = '\n'.join([line for line in git_output.splitlines() if line.startswith('+') or line.startswith('-')])

    # Console output result
    print(filtered_output)
    print("\n\n")
    # Save the results to a file
    with open(output_filename, "w") as file:
        file.write(filtered_output)

def get_commit_id(s):
    # Split the input string and extract the part after 'kernel commit from upstream:'
    parts = s.split('kernel-commit-from-upstream:', 1)
    if len(parts) == 2:
        # Continue to split the string and retrieve the part before the first '}'
        commit_id = parts[1].split('}', 1)[0].strip()
        print(commit_id)
        return commit_id
    else:
        return None


def compare_files(input_oki: str, input_gki: str):

    # Print function name
    #print("\nFunction name: compare_files\n")

    # Check if files are identical
    if filecmp.cmp(input_oki, input_gki):
        print('PASS')
    else:
        print('Files are different')

        # Read file content
        with open(input_oki, 'r') as f1:
            content1 = f1.readlines()

        with open(input_gki, 'r') as f2:
            content2 = f2.readlines()

        # Print file content
        print("Content of {}:".format(input_oki))
        print("".join(content1))

        print("\nContent of {}:".format(input_gki))
        print("".join(content2))

        # Compute differences
        diff = difflib.unified_diff(content1, content2, fromfile=input_oki, tofile=input_gki)

        print('\nDifference part is :')
        print(''.join(list(diff)))

        print("you can use local beyond compare tool compare {} {} in {} \n".format(input_oki,input_gki,kernel_path))

def move_file(source_file, target_path):
    # Check if the source file exists
    if not os.path.isfile(source_file):
        print("ERROR:source file {} is not exist!".format(source_file))
    else:
        # Ensure that the target directory exists
        if not os.path.isdir(target_path):
            print("ERROR:target patch {} is not exist!".format(target_path))
        else:
            # move file
            target_file = os.path.join(target_path, os.path.basename(source_file))
            shutil.move(source_file, target_file)
            print("file kernel_platform/common/{} has been moved to {}".format(source_file,target_file))

def main():
    remote_name = 'ack'
    kernel_path = 'kernel_platform/common'
    output_oplus = "output_oplus.txt"
    output_gki = "output_gki.txt"

    enter_directory(kernel_path)

    username = get_gerrit_username()
    add_remote(username,remote_name)

    git_fetch(remote_name)

    latest_commit_id = get_latest_commit_id()
    latest_commit_message = get_git_log_output(latest_commit_id)
    print("oki commit id is:")
    print(latest_commit_id)
    git_show_filtered(latest_commit_id, output_oplus)

    git_log_commid = get_commit_id(latest_commit_message)
    print("Google commit id is:")
    print(git_log_commid)
    git_show_filtered(git_log_commid, output_gki)

    compare_files(output_oplus, output_gki)
    #move output_oplus.txt and output_gki.txt to ../../, avoid generating new files in the kernel/common repository
    move_file(output_oplus, '../../')
    move_file(output_gki, '../../')

if __name__ == "__main__":
    main()
