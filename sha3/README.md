CS547 Homework SHA3_512 Encryption : 20193577 Hyewon Jeong (2019.10.01.)

===============
Homework Report
===============

SHA3-512 Encryption was tested with SHA3_512 in pycryptodome [1].
	To install and use, Run:
		pip install pycryptodome

Also, to compute hamming distance of two hexadecimal strings, I used Hexadecimal Hamming(hamming_distance function) [2].
	To install and use, ensure you have Python 2.7 or 3.4+, Run:
		pip install hexhamming

In the test process, I 
1. created the bytearray with the size of 1024bytes(8192 bits). 
2. Created new SHA3_512 object 
3. Updated the bytearray created in 1
4. Compared the hamming distance between two hash output generated from bytearrays with 1 bit difference.


References
1. https://pycryptodome.readthedocs.io/en/latest/
2. https://github.com/mrecachinas/hexhamming
