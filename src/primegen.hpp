#pragma once

#include "random.hpp"

#include <cstdint>
#include <cstddef>

template<size_t Bits>
struct PrimeGenerator {
	static_assert(Bits > 0 && (Bits & (Bits - 1)) == 0, "Bits must be a power of 2");

	void generate_primes(mpz_t result) {
		mpz_t candidate;
		mpz_init(candidate);
		
		do {
			random_mpz(candidate, Bits);
		} while (!mpz_probab_prime_p(candidate, 50));
		
		mpz_set(result, candidate);
		mpz_clear(candidate);
	}
};