#include <iostream>

#include "rsa.hpp"

const size_t KEY_SIZE = 4096;

int main() {
	std::cout << "Hello! Welcome to beacon." << std::endl;
	std::cout << "Select an option:" << std::endl;
	std::cout << "[1] Generate RSA keys" << std::endl;
	std::cout << "[2] Encrypt a message" << std::endl;
	std::cout << "[3] Decrypt a message" << std::endl;
	std::cout << "[4] Exit" << std::endl;
	int choice;
	std::cin >> choice;
	if (choice == 1) {
		RSA<KEY_SIZE> rsa;
		std::cout << "Public Key: " << rsa.get_public_key() << std::endl;
		std::cout << "Private Key: " << rsa.get_private_key() << std::endl;
	} else if (choice == 2) {
		std::string public_key;
		std::cout << "Enter public key: ";
		std::cin >> public_key;
		RSA<KEY_SIZE> rsa(public_key);
		std::string plaintext;
		std::cout << "Enter message to encrypt: ";
		std::cin.ignore(); // Clear the newline character from the input buffer
		std::getline(std::cin, plaintext);
		std::string ciphertext = rsa.encrypt(plaintext);
		std::cout << "Encrypted message: " << ciphertext << std::endl;
	} else if (choice == 3) {
		std::string public_key, private_key;
		std::cout << "Enter public key: ";
		std::cin >> public_key;
		std::cout << "Enter private key: ";
		std::cin >> private_key;
		RSA<KEY_SIZE> rsa(public_key, private_key);
		std::string ciphertext;
		std::cout << "Enter message to decrypt: ";
		std::cin >> ciphertext;
		std::string plaintext = rsa.decrypt(ciphertext);
		std::cout << "Decrypted message: " << plaintext << std::endl;
	} else if (choice == 4) {
		return 0;
	} else {
		std::cerr << "Invalid choice." << std::endl;
		return 1;
	}
}