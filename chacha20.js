const le32 = (a, b, c, d) => {
    return (a ^ (b << 8) ^ (c << 16) ^ (d << 24)) >>> 0;
}
const rotl = (a, b) => {
    return (a << b) | (a >>> (32 - b));
}
const QR = (z, a, b, c, d) => {
    z[a] += z[b]; z[d] ^= z[a]; z[d] = rotl(z[d], 16);
    z[c] += z[d]; z[b] ^= z[c]; z[b] = rotl(z[b], 12);
    z[a] += z[b]; z[d] ^= z[a]; z[d] = rotl(z[d], 8);
    z[c] += z[d]; z[b] ^= z[c]; z[b] = rotl(z[b], 7);
    z[a] >>>= 0;
    z[b] >>>= 0;
    z[c] >>>= 0;
    z[d] >>>= 0;
}
const chacha20_keystream = (_key, _nonce, counter) => {
    var state = [];
    //Constant
    state[0] = 1634760805;
    state[1] = 857760878;
    state[2] = 2036477234;
    state[3] = 1797285236;
    //Key
    state[4] = le32(_key[0], _key[1], _key[2], _key[3]);
    state[5] = le32(_key[4], _key[5], _key[6], _key[7]);
    state[6] = le32(_key[8], _key[9], _key[10], _key[11]);
    state[7] = le32(_key[12], _key[13], _key[14], _key[15]);
    state[8] = le32(_key[16], _key[17], _key[18], _key[19]);
    state[9] = le32(_key[20], _key[21], _key[22], _key[23]);
    state[10] = le32(_key[24], _key[25], _key[26], _key[27]);
    state[11] = le32(_key[28], _key[29], _key[30], _key[31]);
    //Counter
    state[12] = counter;
    //Nonce
    state[13] = le32(_nonce[0], _nonce[1], _nonce[2], _nonce[3]);
    state[14] = le32(_nonce[4], _nonce[5], _nonce[6], _nonce[7]);
    state[15] = le32(_nonce[8], _nonce[9], _nonce[10], _nonce[11]);
    var temp = state.slice();
    for (let i = 0; i < 10; i++) {
        //Odd round
        QR(temp, 0, 4, 8, 12);	// 1st column
        QR(temp, 1, 5, 9, 13);	// 2nd column
        QR(temp, 2, 6, 10, 14);	// 3rd column
        QR(temp, 3, 7, 11, 15);	// 4th column
        // Even round
        QR(temp, 0, 5, 10, 15);	// diagonal 1 (main diagonal)
        QR(temp, 1, 6, 11, 12);	// diagonal 2
        QR(temp, 2, 7, 8, 13);	// diagonal 3
        QR(temp, 3, 4, 9, 14);	// diagonal 4 
        //
    }
    var stream = [];

    for (let i = 0, i2 = 0; i < 16; i++) {
        state[i] += temp[i];

        stream[i2++] = state[i] & 0xFF
        stream[i2++] = (state[i] >>> 8) & 0xFF
        stream[i2++] = (state[i] >>> 16) & 0xFF
        stream[i2++] = (state[i] >>> 24) & 0xFF
    }
    state = null;
    temp = null;

    return stream;
}
const chacha20_xor = (_key, _nonce, counter, plaintext) => {
    var keystream = chacha20_keystream(_key, _nonce, counter);
    let pos = 0;
    for (let i = 0; i < plaintext.length; i++) {
        if (pos === 64) {
            counter++;
            keystream = chacha20_keystream(_key, _nonce, counter);
            pos = 0;
        }
        plaintext[i] ^= keystream[pos++];
    }
}
