#pragma once

#include <gmpxx.h>
#include <iostream>
#include <string>

#include "primegen.hpp"

template<size_t key_sz>
class RSA {
private:
	mpz_t p, q;
	mpz_t phi; // totient of n
	mpz_t d; // private key
	bool full_mode = true; // full mode = encrypt, decrypt; false = encrypt only

public:
	static_assert(key_sz >= 2048, "Don't be insecure!");

	mpz_t n; // mod
	mpz_t e; // expo (public key)

	RSA() {
		mpz_init(p);
		mpz_init(q);
		PrimeGenerator<key_sz / 2> prime_gen; // divide by 2 for p and q so that p * q is key_sz bits
		prime_gen.generate_primes(p);
		prime_gen.generate_primes(q);

		mpz_init(n);
		mpz_mul(n, p, q); // n = p * q
		
		mpz_t p_minus_1, q_minus_1;
		mpz_init(p_minus_1);
		mpz_init(q_minus_1);
		mpz_sub_ui(p_minus_1, p, 1); // p - 1
		mpz_sub_ui(q_minus_1, q, 1); // q - 1
		mpz_init(phi);
		mpz_mul(phi, p_minus_1, q_minus_1); // phi = (p-1) * (q-1)
		mpz_clear(p_minus_1);
		mpz_clear(q_minus_1);

		mpz_init(e);
		mpz_set_ui(e, 65537); // generally used

		mpz_init(d);
		if (mpz_invert(d, e, phi) == 0) {
			std::cerr << "Error: Could not compute modular inverse of e and phi." << std::endl;
			std::cerr << "This may happen if e and phi are not coprime." << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	RSA(const std::string& public_key) {
		mpz_init(n);
		if (mpz_set_str(n, public_key.c_str(), 10) != 0) {
			std::cerr << "Error: Invalid public key format." << std::endl;
			exit(EXIT_FAILURE);
		}

		mpz_init(e);
		mpz_set_ui(e, 65537);

		mpz_init(p);
		mpz_init(q);
		mpz_init(phi);
		mpz_init(d);

		full_mode = false; // only encrypt mode
	}

	RSA(const std::string& public_key, const std::string& private_key) {
		mpz_init(n);
		if (mpz_set_str(n, public_key.c_str(), 10) != 0) {
			std::cerr << "Error: Invalid public key format." << std::endl;
			exit(EXIT_FAILURE);
		}

		mpz_init(e);
		mpz_set_ui(e, 65537);

		mpz_init(d);
		if (mpz_set_str(d, private_key.c_str(), 10) != 0) {
			std::cerr << "Error: Invalid private key format." << std::endl;
			exit(EXIT_FAILURE);
		}
	}
	
	std::string get_public_key() const {
		// Literally just n since e is always 65537
		char* n_str = mpz_get_str(nullptr, 10, n);
		std::string public_key(n_str);
		free(n_str); // Free the string allocated by mpz_get_str
		return public_key;
	}

	std::string get_private_key() const {
		char* d_str = mpz_get_str(nullptr, 10, d);
		std::string private_key(d_str);
		free(d_str); // Free the string allocated by mpz_get_str
		return private_key;
	}

	std::string encrypt(std::string plaintext) const {
		// treat plaintext as a base-256 number
		// first, chunk it into segments of size like 16 chars to prevent overflow
		std::string ciphertext;
		const size_t chunk_sz = key_sz / 128;
		while (plaintext.size() % chunk_sz != 0) {
			plaintext.push_back(0); // pad with null characters to make it a multiple of chunk_sz
		}
		size_t sz = plaintext.size();
		for (size_t i = 0; i < sz; i += chunk_sz) {
			size_t chunk_size = std::min<size_t>(chunk_sz, sz - i);
			std::string chunk = plaintext.substr(i, chunk_size);

			mpz_t m; // plaintext as a number
			mpz_init(m);
			mpz_import(m, chunk_size, 1, sizeof(chunk[0]), 0, 0, chunk.data()); // import the chunk as a number

			mpz_t c; // ciphertext
			mpz_init(c);
			mpz_powm(c, m, e, n); // c = m^e mod n

			char* c_str = mpz_get_str(nullptr, 10, c);
			ciphertext += std::string(c_str) + "-"; // append the ciphertext segment
			free(c_str); // Free the string allocated by mpz_get_str

			mpz_clear(m);
			mpz_clear(c);
		}
		return ciphertext;
	}

	std::string decrypt(const std::string& ciphertext) const {
		if (!full_mode) {
			std::cerr << "Error: This RSA instance is in encrypt-only mode." << std::endl;
			exit(EXIT_FAILURE);
		}

		std::string plaintext;
		size_t pos = 0;
		size_t next_pos;
		while ((next_pos = ciphertext.find('-', pos)) != std::string::npos) {
			std::string segment = ciphertext.substr(pos, next_pos - pos);
			pos = next_pos + 1;
			mpz_t c; // ciphertext segment as a number
			mpz_init(c);
			if (mpz_set_str(c, segment.c_str(), 10) != 0) {
				std::cerr << "Error: Invalid ciphertext segment format." << std::endl;
				mpz_clear(c);
				exit(EXIT_FAILURE);
			}
			mpz_t m; // decrypted plaintext segment
			mpz_init(m);
			mpz_powm(m, c, d, n); // m = c^d
			size_t chunk_size = mpz_sizeinbase(m, 256); // size in
			unsigned char* chunk_data = new unsigned char[chunk_size];
			mpz_export(chunk_data, nullptr, 1, sizeof(unsigned char), 0, 0, m); // export the decrypted segment
			plaintext.append(reinterpret_cast<char*>(chunk_data), chunk_size); // append the decrypted segment
			delete[] chunk_data; // Free the allocated memory for the chunk data
			mpz_clear(c);
			mpz_clear(m);
		}
		return plaintext;
	}
};