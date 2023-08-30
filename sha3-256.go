package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

const blockSize = 136

// Функция rho
func leftRotate(x uint64, i uint) uint64 {
	return (x << i) | (x >> (64 - i))
}

func theta(A []uint64) {
	
	C := [5]uint64{}
	D := [5]uint64{}

	// Вычисление C[i] на основе операции XOR
	for i := 0; i < 5; i++ {
		C[i] = A[i] ^ A[i+5] ^ A[i+10] ^ A[i+15] ^ A[i+20]
	}

	// Вычисление D[i] с помощью циклического сдвига и XOR
	for i := 0; i < 5; i++ {
		D[i] = leftRotate(C[(i+1)%5], 1) ^ C[(i+4)%5]
	}

	// Применение D[j] к элементам массива A через операцию XOR
	for i := 0; i < 25; i += 5 {
		for j := 0; j < 5; j++ {
			A[j+i] ^= D[j]
		}
	}
}

func pi(A []uint64) {
	A1 := A[1]
	A[1] = A[6]
	A[6] = A[9]
	A[9] = A[22]
	A[22] = A[14]
	A[14] = A[20]
	A[20] = A[2]
	A[2] = A[12]
	A[12] = A[13]
	A[13] = A[19]
	A[19] = A[23]
	A[23] = A[15]
	A[15] = A[4]
	A[4] = A[24]
	A[24] = A[21]
	A[21] = A[8]
	A[8] = A[16]
	A[16] = A[5]
	A[5] = A[3]
	A[3] = A[18]
	A[18] = A[17]
	A[17] = A[11]
	A[11] = A[7]
	A[7] = A[10]
	A[10] = A1
}

func chi(A []uint64) {
	for i := 0; i < 25; i += 5 {
		A0 := A[0+i]
		A1 := A[1+i]
		A[0+i] ^= (^A1) & A[2+i]
		A[1+i] ^= (^A[2+i]) & A[3+i]
		A[2+i] ^= (^A[3+i]) & A[4+i]
		A[3+i] ^= (^A[4+i]) & A0
		A[4+i] ^= (^A0) & A1
	}
}

var RC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
	0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var shifts = [25]uint{
	1, 62, 28, 27, 36,
	44, 6, 55, 20, 3,
	10, 43, 25, 39, 41,
	45, 15, 21, 8, 18,
	2, 61, 56, 14, 0,
}

func KeccakF(state []uint64) {
	for round := 0; round < 24; round++ {
		theta(state)

		for i := 1; i <= 24; i++ {
			state[i] = leftRotate(state[i], shifts[i-1])
		}

		pi(state)
		chi(state)

		state[0] ^= RC[round]
	}
}

func iteration(data []byte, h []uint64) {
	// Преобразование блока данных и применение функции KeccakF
	for i := 0; i <= 16; i++ {
		var value uint64
		for j := 0; j < 8; j++ {
			value |= uint64(data[8*i+j]) << (j * 8)
		}
		h[i] ^= value
	}
	KeccakF(h)
}

func processFullBlocks(dataBytes []byte, numBlocks int, state []uint64) {
	for i := 0; i < numBlocks; i++ {
		iteration(dataBytes[i*blockSize:], state)
	}
}

func RemainBytes(dataBytes []byte, len, remainingBytes int, state []uint64) {
	buffer := make([]byte, blockSize)
	copy(buffer, dataBytes[len-remainingBytes:])

	buffer[remainingBytes] |= 0x06
	buffer[blockSize-1] |= 0x80

	iteration(buffer, state)
}

func copyHashToOutput(state []uint64, hash []byte) {
	for i := 0; i < len(hash)/8; i++ {
		binary.LittleEndian.PutUint64(hash[i*8:], state[i])
	}
}

func sha3(data []byte, hash []byte) {
	dataBytes := data

	state := make([]uint64, 25)

	numFullBlocks := len(data) / blockSize
	processFullBlocks(dataBytes, numFullBlocks, state)
	remainingBytes := len(data) % blockSize
	RemainBytes(dataBytes, len(data), remainingBytes, state)

	copyHashToOutput(state, hash)
}

func main() {
	startTime := time.Now()

	var hashInput [32]byte

	fmt.Print("Enter a message: ")
	input := bufio.NewReader(os.Stdin)
	message, _ := input.ReadString('\n')
	message = message[:len(message)-1]

	fmt.Print("Enter the filename to hash its content: ")
	filename, _ := input.ReadString('\n')
	filename = filename[:len(filename)-1]

	// Хеширование введенной строки
	sha3([]byte(message), hashInput[:])

	// Вывод результатов хеширования строки
	fmt.Println("Hash for input message:")
	fmt.Printf("%x\n", hashInput)

	// Попытка открыть файл и хешировать его содержимое
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening the file:", err)
		return
	}
	defer file.Close()

	state := make([]uint64, 25)

	for {
		buffer := make([]byte, blockSize)
		bytesRead, err := file.Read(buffer)

		if err != nil && err != io.EOF {
			fmt.Println("Error reading the file:", err)
			return
		}

		if bytesRead > 0 {
			if bytesRead == blockSize {
				// Обработка полного блока
				processFullBlocks(buffer, blockSize/blockSize, state)
			} else {
				// Обработка оставшихся байтов
				RemainBytes(buffer, bytesRead, bytesRead, state)
			}
		}

		if err == io.EOF {
			break
		}
	}

	// Вывод результатов хеширования файла
	hashFile := make([]byte, 32)
	copyHashToOutput(state, hashFile)
	fmt.Println("Hash for file content:")
	fmt.Printf("%x\n", hashFile)

	elapsedTime := time.Since(startTime)
	fmt.Printf("Время выполнения: %s\n", elapsedTime)
}
