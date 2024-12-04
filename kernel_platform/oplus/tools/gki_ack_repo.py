import subprocess
import os
import shutil

def create_and_enter_directory(dir_name="ack"):
    # if the directory does not exist, create this directory
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

    # otherwise, if the directory exists, delete all files and directories under the directory
    else:
        for item in os.listdir(dir_name):
            item_path = os.path.join(dir_name, item)

            # determine item_ Is path a directory? If so, use rmtree to delete the directory, its subdirectories, and files
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            elif os.path.islink(item_path):  # Check if it's a symbolic link
                os.unlink(item_path)  # Remove the symbolic link using os.unlink()
            else:
                os.remove(item_path)

    # enter this directory
    os.chdir(dir_name)


def run_repo_cmd():
    repo_cmd = [
        "repo",
        "init",
        "-u",
        "https://android.googlesource.com/kernel/manifest",
        "-b",
        "common-android14-6.1",
        "-m",
        "default.xml",
        "--no-repo-verify",
        "--repo-branch=update",
    ]

    try:
        process = subprocess.Popen(repo_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())
        process.poll()

        print("Repo command executed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error executing repo command.")
        print("Return code:", e.returncode)
        print("Output:")
        print(e.output)



def run_repo_sync():
    repo_sync_cmd = [
        "repo",
        "sync",
        "-fcq",
        "-j4",
        "--no-tags",
        "--prune",
        "--no-repo-verify"
    ]

    try:
        process = subprocess.Popen(repo_sync_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())
        process.poll()

        print("Repo sync command executed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error executing repo sync command.")
        print("Return code:", e.returncode)
        print("Output:")
        print(e.output)


def run_bazel_cmd():
    bazel_cmd = [
        "tools/bazel",
        "run",
        "//common:kernel_aarch64_abi_dist",
        "--",
        "--dist_dir=out/dist",
    ]

    try:
        process = subprocess.Popen(bazel_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                print(output.strip())
        process.poll()

        print("Bazel command executed successfully.")
    except subprocess.CalledProcessError as e:
        print("Error executing Bazel command.")
        print("Return code:", e.returncode)
        print("Output:")
        print(e.output)



def main():
    create_and_enter_directory()
    run_repo_cmd()
    run_repo_sync()
    run_bazel_cmd()

if __name__ == "__main__":
    main()
