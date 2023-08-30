#include <iostream>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <vector>
#include <chrono>

using namespace std;
using namespace std::chrono;

constexpr size_t block_size = 136;  

// function rho 
uint64_t left_rotate(uint64_t x, const size_t i) {
    return x << i | x >> (sizeof(uint64_t) * 8 - i);
}

void theta(uint64_t A[]) {
    uint64_t C[5], D[5];
     // Вычисление C[i] на основе операции XOR
    for (size_t i = 0; i < 5; ++i)
        C[i] = A[i] ^ A[i + 5] ^ A[i + 10] ^ A[i + 15] ^ A[i + 20];
    // Вычисление D[i] с помощью циклического сдвига и XOR
    for (size_t i = 0; i < 5; ++i) {
        D[i] = left_rotate(C[(i + 1) % 5], 1) ^ C[(i + 4) % 5];
    }
    // Применение D[j] к элементам массива A через операцию XOR
    for (size_t i = 0; i < 25; i += 5) {
        for (size_t j = 0; j < 5; ++j) {
            A[j + i] ^= D[j];
        }
    }
}

void pi(uint64_t A[]) {
    // операции перестановки элементов массива
    uint64_t A1 = A[1];
    A[ 1] = A[ 6];  A[ 6] = A[ 9];  A[ 9] = A[22];  A[22] = A[14];
    A[14] = A[20];  A[20] = A[ 2];  A[ 2] = A[12];  A[12] = A[13];
    A[13] = A[19];  A[19] = A[23];  A[23] = A[15];  A[15] = A[ 4];
    A[ 4] = A[24];  A[24] = A[21];  A[21] = A[ 8];  A[ 8] = A[16];
    A[16] = A[ 5];  A[ 5] = A[ 3];  A[ 3] = A[18];  A[18] = A[17];
    A[17] = A[11];  A[11] = A[ 7];  A[ 7] = A[10];  A[10] = A1;
}
void chi(uint64_t A[]) {
    // операции логических операций над элементами массива
    for (size_t i = 0; i < 25; i += 5) {
        uint64_t A0 = A[0 + i], A1 = A[1 + i];
        A[0 + i] ^= (~A1) & A[2 + i];
        A[1 + i] ^= (~A[2 + i]) & A[3 + i];
        A[2 + i] ^= (~A[3 + i]) & A[4 + i];
        A[3 + i] ^= (~A[4 + i]) & A0;
        A[4 + i] ^= (~A0) & A1;
    }
}

// Константы для раундов
constexpr uint64_t RC[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    };

// Constants for rho (для сдвигов)
constexpr size_t shifts[25] = {
        1,  62, 28, 27, 36,
        44,  6, 55, 20,  3,
        10,  43, 25, 39, 41,
        45, 15, 21,  8, 18,
        2,  61, 56, 14, 0 
    }; 
// Функция выполнения раундов алгоритма Keccak
void KeccakF(uint64_t state[]) {   
    // *выполнение раундов с применением функций theta, pi, chi и XOR с константами
    for (size_t round = 0; round < 24; round++) {
        theta(state);

        for (size_t i = 1; i <= 24; ++i) {
            state[i] = left_rotate(state[i], shifts[i - 1]);
        }

        pi(state);
        chi(state);

        *state ^= RC[round];
    }
}
// Функция выполнения одной итерации хеширования
void iteration(const uint8_t* data, uint64_t h[]) {
     // *преобразование блока данных и применение функции KeccakF
    for (size_t i = 0; i <= 16; ++i) {
        uint64_t value = 0;
        for (size_t j = 0; j < 8; ++j) {
            value |= uint64_t(data[8 * i + j]) << (j * 8);
        }
        h[i] ^= value;
    }
    KeccakF(h);
}

//*Дополнение (processFullBlocks and RemainBytes)*//
// Функция обработки полных блоков данных
void processFullBlocks(const uint8_t* dataBytes, size_t numBlocks, uint64_t state[]) {
    for (size_t i = 0; i < numBlocks; ++i) {
        iteration(dataBytes + i * block_size, state);
    }
}
// Функция обработки оставшихся байтов данных
void RemainBytes(const uint8_t* dataBytes, size_t len, size_t remainingBytes, uint64_t state[]) {
    uint8_t buffer[block_size] = {0};
    memcpy(buffer, dataBytes + len - remainingBytes, remainingBytes);

    buffer[remainingBytes] |= 0x06;
    buffer[block_size - 1] |= 0x80;

    iteration(buffer, state);
}


//*Выжимание (copyHashToOutput and sha3)*//
// Функция копирования хеша в выходной буфер
void copyHashToOutput(uint64_t state[], char* hash) {
    memcpy(hash, state, 32);
}

// Основная функция хеширования
void sha3(const void* data, size_t len, char* hash) {
      // *основной поток хеширования: обработка полных блоков и оставшихся байтов, копирование хеша
    const uint8_t* dataBytes = reinterpret_cast<const uint8_t*>(data);

    uint64_t state[25] = {0};

    size_t numFullBlocks = len / block_size;
    processFullBlocks(dataBytes, numFullBlocks, state);
    size_t remainingBytes = len % block_size;
    RemainBytes(dataBytes, len, remainingBytes, state);

    copyHashToOutput(state, hash);
}

int main() {
    auto start = high_resolution_clock::now();

    // Буфер для хешей
    uint8_t hash_input[32];

    string input;
    cout << "Enter a message: ";
    getline(cin, input);

    string filename;
    cout << "Enter the filename to hash its content: ";
    getline(cin, filename);

    // Хеширование введенной строки
    sha3(input.data(), input.length(), reinterpret_cast<char*>(hash_input));

    // Вывод результатов хеширования строки
    cout << "Hash for input message:\n";
    for (int i = 0; i < 32; ++i)
        printf("%02x", int(hash_input[i]) & 0xff);
    printf("\n");

    // Попытка открыть файл и хешировать его содержимое
    ifstream file(filename, ios::binary);
    if (file) {
        uint64_t state[25] = {0};  // Инициализация состояния для файла

        while (file) {
            uint8_t buffer[136];  
            file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
            size_t bytes_read = file.gcount();

            if (bytes_read > 0) {
                if (bytes_read == sizeof(buffer)) {
                    // Обработка полного блока
                    processFullBlocks(buffer, sizeof(buffer) / block_size, state);
                } else {
                    // Обработка оставшихся байтов
                    RemainBytes(buffer, bytes_read, bytes_read, state);
                }
            }
        }

        // Вывод результатов хеширования файла
        char hash_file[32];
        copyHashToOutput(state, hash_file);
        cout << "Hash for file content:\n";
        for (int i = 0; i < 32; ++i)
            printf("%02x", int(hash_file[i]) & 0xff);
        printf("\n");
    } else {
        cerr << "Error opening the file." << endl;
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start);

    cout << "Time taken: " << duration.count() << " milliseconds" << endl;

    return 0;
}


