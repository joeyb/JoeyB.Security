# JoeyB.Security

This project contains some security-related utilities in C#/.NET that I've found useful.

## Crypto

The crypto/hash functionality has been extracted from the [StackExchange OpenID Provider](http://code.google.com/p/stackid/).

Most password hashing implementations that I've seen in .NET use MD5 or SHA, which are both general purpose hashing algorithms. They are both poor choices for hashing passwords because they are actually too fast. With modern computing power (especially CUDA on GPUs) an attacker can brute-force those passwords in a reasonable amount of time, even if the password is salted.

This library instead uses the built-in .NET implementation of [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2). It is orders of magnitude slower than MD5 or SHA (which is a good thing in this case) and it can easily be scaled to take more time as CPU power increases.

Hashing a new password simply involves generating a new salt, then hashing the password with the new salt:

    var password = "testpassword";

    var salt = Cryptography.GenerateSalt();
	
	var hashedPassword = Cryptography.Hash(password, salt);
