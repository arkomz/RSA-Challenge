# RSA-Challenge
Initializes Public and Private RSA Keys, utilizes Shamir's Secret Sharing Algorithm to divide a secret into n parts. From there, at least k are needed to reconstruct the secret. 

How I went about implementing SSSA: 

Shamir's Secret Sharing algorithm only works for finite fields, so I went and made a class that handles all the operations in Byte256. 


This library performs all operations in Byte256. Each byte of a secret is encoded as a separate Byte256 polynomial, and the resulting parts are the aggregated values of those polynomials.





