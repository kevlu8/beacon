#include "random.hpp"
#include <iostream>

void random_mpz(mpz_t result, size_t bits) {
	uint64_t seed;
	std::ifstream urandom("/dev/urandom", std::ios::binary);
	if (urandom) {
		urandom.read(reinterpret_cast<char*>(&seed), sizeof(seed));
	} else {
		// Fallback to using the current time as a seed if /dev/urandom is not available
		std::cerr << "Warning: /dev/urandom not available, using current time as seed. This is NOT secure!" << std::endl;
		seed = std::chrono::system_clock::now().time_since_epoch().count();
	}
	urandom.close();

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, seed);

	mpz_rrandomb(result, state, bits);
	gmp_randclear(state);
}