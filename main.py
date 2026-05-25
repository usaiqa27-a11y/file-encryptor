import sys
from gui.app import SecureCryptoApp

def main():
    try:
        app = SecureCryptoApp()
        app.mainloop()
    except KeyboardInterrupt:
        print("\n[!] Execution cycle interrupted safely. Cleaning environment memory space.")
        sys.exit(0)

if __name__ == "__main__":
    main()