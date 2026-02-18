from getpass import getpass

from core.auth import make_password_hash


def main() -> None:
    password = getpass("Enter password: ")
    confirm = getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    print(make_password_hash(password))


if __name__ == "__main__":
    main()
