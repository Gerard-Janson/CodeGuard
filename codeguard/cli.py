import pyfiglet
import sys

def local_run():
    print("TODO")

def repo_run():
    print("TODO")

def password_check():
    print("TODO")

def show_menu():
    result = pyfiglet.figlet_format("CODEGUARD",font = "pagga")
    print(result)
        
    print("1. Run Local Scan")
    print("2. Run Repo")
    print("3. Password Check")
    print("4. Exit")
    
def main():
    while True:
        show_menu()
        choice = input("Please select a number: ")

        choice = int(choice)

        match choice:
            case 1:
                local_run()
            case 2:
                repo_run()
            case 3:
                password_check()
            case 4:
                print("Goodbye!")
                sys.exit()

        


