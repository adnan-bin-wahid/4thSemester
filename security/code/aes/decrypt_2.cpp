/* decrypt.cpp
 * Performs decryption using AES 128-bit
 * @author Cecelia Wisniewska
 */
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include "structures.h"

using namespace std;

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 * So basically does the same as AddRoundKey in the encryption
 */
void SubRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
void InverseMixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

// Shifts rows right (rather than left) for decryption
void ShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
void SubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
void Round(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

// Same as Round() but no InverseMixColumns
void InitialRound(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	ShiftRows(state);
	SubBytes(state);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
void AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage)
{
	unsigned char state[16]; // Stores the first 16 bytes of encrypted message

	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey+160);

	int numberOfRounds = 9;

	for (int i = 8; i >= 0; i--) {
		Round(state, expandedKey + (16 * (i + 1)));
	}

	SubRoundKey(state, expandedKey); // Final round

	// Copy decrypted state to buffer
	for (int i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
}

void HexStringToBinary(const string &hexString, unsigned char *binaryData) {
    for (size_t i = 0; i < hexString.length(); i += 2) {
        string byteString = hexString.substr(i, 2);
        binaryData[i / 2] = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
    }
}

int main() {
    cout << "=============================" << endl;
    cout << " 128-bit AES Decryption Tool " << endl;
    cout << "=============================" << endl;

    // Read in the encrypted message from encrypted_msg.txt
    ifstream encryptedFile("encrypted_msg.txt");
    stringstream buffer;
    buffer << encryptedFile.rdbuf();
    string encryptedMessageHex = buffer.str();
    encryptedFile.close();

    // Convert the encrypted message from hexadecimal to binary
    size_t binaryLength = encryptedMessageHex.length() / 2; // Each byte is represented by 2 characters
    unsigned char *encryptedMessage = new unsigned char[binaryLength];
    HexStringToBinary(encryptedMessageHex, encryptedMessage);

    // Read the key from keyfile
    ifstream keyFile("keyfile");
    if (!keyFile) {
        cout << "Error: Unable to open keyfile for reading" << endl;
        delete[] encryptedMessage;
        return 1;
    }

    string keyStr;
    getline(keyFile, keyStr);
    keyFile.close();

    // Convert the key string to an array of unsigned char
    unsigned char key[16];
    istringstream hexCharsStream(keyStr);
    int idx = 0;
    unsigned int c;
    while (hexCharsStream >> hex >> c) {
        key[idx++] = static_cast<unsigned char>(c);
    }

    // Generate the expanded key
    unsigned char expandedKey[176];
    KeyExpansion(key, expandedKey);

    // Decrypt the message
    size_t messageLen = encryptedMessageHex.length() / 2; // Length of the original message
    unsigned char *decryptedMessage = new unsigned char[messageLen];
    AESDecrypt(encryptedMessage, expandedKey, decryptedMessage);

    // Write the decrypted message to decrypted_msg.txt
    ofstream decryptedFile("decrypted_msg.txt");
    if (!decryptedFile) {
        cout << "Error: Unable to open decrypted_msg.txt for writing" << endl;
        delete[] encryptedMessage;
        delete[] decryptedMessage;
        return 1;
    }

    decryptedFile.write(reinterpret_cast<char *>(decryptedMessage), messageLen);
    decryptedFile.close();

    // Free memory
    delete[] encryptedMessage;
    delete[] decryptedMessage;

    cout << "Decryption successful. Decrypted message written to decrypted_msg.txt" << endl;

    return 0;
}