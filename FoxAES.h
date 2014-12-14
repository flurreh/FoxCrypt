/*
	Copyright (c) 2014 github.com/flurreh

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in
	all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	THE SOFTWARE.
*/

#ifndef __FOXCRYPT__AES__H__
#define __FOXCRYPT__AES__H__

#include <cstdint>
#include <stdlib.h>

namespace FoxCrypt {

	/**
	* \enum	FOXAES_ERRORS
	*
	* \brief	Error values that may be returned by FoxAES' functions
	*/
	enum FOXAES_ERRORS {
		// no error
		AES_ERROR_OK = 0x00000000,

		// no input key given
		AES_ERROR_NO_IN_KEY = 0xffff0001,

		// wrong key size given (see AES_KEY_SIZE for valid sizes)
		AES_ERROR_WRONG_KEYSIZE = 0xffff0002,

		// no input buffer given
		AES_ERROR_NO_INPUT_BUFFER = 0xffff0003,

		// no output buffer given
		AES_ERROR_NO_OUTPUT_BUFFER = 0xffff0004,

		// no encryption key has been set
		AES_ERROR_NO_ENC_KEY_SET = 0xffff0005,

		// no decryption key has been set
		AES_ERROR_NO_DEC_KEY_SET = 0xffff0006,
	};


	/**
	* \enum	AES_KEY_SIZE
	*
	* \brief	Valid AES key sizes (128, 192 and 256 bits).
	*/
	enum AES_KEY_SIZE {
		AES_128 = 128,
		AES_192 = 192,
		AES_256 = 256,
	};


	/**
	* \class	AES
	*
	* \brief	Implementation of the AES encryption cipher.
	*/
	class AES {
	public:

		/**
		* \fn	AES::AES();
		*
		* \brief	Default constructor.
		*/
		AES();

		/**
		* \fn	AES::~AES();
		*
		* \brief	Destructor.
		*/
		~AES();

		/**
		* \fn	int AES::SetEncryptionKey(const uint8_t *key, const AES_KEY_SIZE keySize);
		*
		* \brief	Expand the cipher key into the encryption key schedule.
		*
		* \param	key	   	Pointer to the key.
		* \param	keySize	Size of the key.
		*
		* \return	An error message (see FOXAES_ERRORS).
		*/
		int SetEncryptionKey(const uint8_t *key, const AES_KEY_SIZE keySize);

		/**
		* \fn	int AES::SetDecryptionKey(const uint8_t *key, const AES_KEY_SIZE keySize);
		*
		* \brief	Expand the cipher key into the decryption key schedule.
		*
		* \param	key	   	Pointer to the key.
		* \param	keySize	Size of the key.
		*
		* \return	An error message (see FOXAES_ERRORS).
		*/
		int SetDecryptionKey(const uint8_t *key, const AES_KEY_SIZE keySize);

		/**
		* \fn	int AES::EncryptBlock(const uint8_t *in, uint8_t *out);
		*
		* \brief	Encrypts a single block. In and out can overlap.
		*
		* \param	in		   	Pointer to the unencrypted block.
		* \param [in,out]	out	Pointer to the encrypted block.
		*
		* \return	An error message (see FOXAES_ERRORS).
		*/
		int EncryptBlock(const uint8_t *in, uint8_t *out);

		/**
		* \fn	int AES::DecryptBlock(const uint8_t *in, uint8_t *out);
		*
		* \brief	Decrypts a single block. In and out can overlap.
		*
		* \param	in		   	Pointer to the encrypted block.
		* \param [in,out]	out	Pointer to the unencrypted block.
		*
		* \return	An error message (see FOXAES_ERRORS).
		*/
		int DecryptBlock(const uint8_t *in, uint8_t *out);

	private:
		// transformations for the encryption
		static const uint32_t m_te0[256];
		static const uint32_t m_te1[256];
		static const uint32_t m_te2[256];
		static const uint32_t m_te3[256];

		// transformations for the decryption
		static const uint32_t m_td0[256];
		static const uint32_t m_td1[256];
		static const uint32_t m_td2[256];
		static const uint32_t m_td3[256];
		static const uint8_t m_td4[256];

		// round constant words
		static const uint32_t m_rcon[];

		// max round count
		static const uint8_t m_aesMaxRounds = 14;

		// size of a single block
		static const uint8_t m_aesBlockSize = 16;

		// holds our current encryption round key
		uint32_t m_encRoundKey[4 * (m_aesMaxRounds + 1)];

		// holds our current decryption round key
		uint32_t m_decRoundKey[4 * (m_aesMaxRounds + 1)];

		// round count
		uint8_t m_roundCount;

		// true when the encryption key has been set
		bool m_encKeySet;

		// true when the decryption key has been set
		bool m_decKeySet;
	};
}

#endif //__FOXCRYPT__AES__H__