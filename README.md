# RSA-Challenge
Initializes Public and Private RSA Keys 

How I went about implementing SSSA: 

Shamir's Secret Sharing algorithm only works for finite fields, so I went and made a class that handles all the operations in Byte256. 


and this library performs all operations in GF(256). Each byte of a secret is encoded as a separate Byte(256) polynomial, and the resulting parts are the aggregated values of those polynomials.





