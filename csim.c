/*
 * csim.c
 * Taylor Wong and Cecilia Barnhill
 * Program Description: Simulator will take in the same command line arguments
 * as csim-ref and produce the identical output as the reference simulator.
 * Project Bucks: 0
 * Number of Hours Spent:17 
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "cachelab.h"
#include "readfile.h"
#include <string.h>
#include <math.h>

typedef unsigned long int mem_addr;

/* 
 * Struct to represent a single line in a set and will track whether the line
 * is empty or not, the tag of the line, and LRU bit.
 */
struct Line
{
	unsigned int valid;
	unsigned int tag;
	unsigned int lru;
};
typedef struct Line Line;

/*
 * Struct to represent a single set in a cache.
 * Each set has a number of lines available for data.
 */
struct Set
{
	int num_lines;
	Line *lines;
};
typedef struct Set Set;

/*
 * Struct to represent a cache.
 * A cache has a set number of sets to store data in.
 */
struct Cache
{
	int num_sets;
	Set *Sets;
};
typedef struct Cache Cache;

// forward declarations
void simulateCache(char *trace_file, int num_sets, int block_size, int lines_per_set, int verbose);
void unpack(mem_addr address, int set_bits, int offset_bits, int *set, int *tag);
int isinCache(Cache *cache, mem_addr address, int set, int tag, int *line);
int updateCache(Cache *cache, int set, int tag, mem_addr address);
void updateLRU(Cache *cache, int set, int line);
void initCache(Cache *cache, int num_sets, int lines_per_set);
void freeCache(Cache *cache);
void dataAccess(Cache *cache, mem_addr addr, char *oper, int size, int verbose, int *hit_count, int *miss_count, int *evic_count, int set, int tag, int *line);

/**
 * Prints out a reminder of how to run the program.
 * 
 * @param executable_name Strign containing the name of the executable.
 */
void usage(char *executable_name) {
	printf("Usage: %s [-hv] -s <s> -E <E> -b <b> -t <tracefile> \n", executable_name);
}

int main(int argc, char *argv[]) {

	int verbose_mode = 0;
	int num_sets = 0;
	int set_bits = 0;
	char *trace_filename = NULL;
	int lines_per_set = 0;
	int offset_bits = 0;
	int block_size = 0;
	opterr = 0;
	int c = -1;

	while ((c = getopt(argc, argv, "vs:E:b:t:")) != -1) {
		switch (c) {
			case 'v':
				// enable verbose mode
				verbose_mode = 1;
				break;
			case 's':
				// specify the number of sets
				set_bits = strtol(optarg, NULL, 10);
				num_sets = 1 << set_bits;
				break;
			case 't':
				// specify the trace filename
				trace_filename = optarg;
				break;
			case 'h':
				// print usage info
				printf("Options: \n");
				printf("\t -h \t \t \t Print this help message. \n");
				printf("\t -v \t \t \t Optional verbose flag. \n");
				printf("\t -s <num> \t Number of set index bits. \n");
				printf("\t -E <num> \t Number of lines per set. \n");
				printf("\t -b <num> \t Number of block offset bits. \n");
				printf("\t -t <file> \t Trace file.\n");
				printf("\n");
				printf("Examples: \n");
				printf(" \t linux> ./csim -s 4 -E 1 -b 4 -t traces/yi.trace \n");
				printf(" \t linux> ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace \n");	
				break;
			case 'E':
				// number of lines per set
				lines_per_set = strtol(optarg, NULL, 10);
				break;
			case 'b':
				// number of block offset bits
				offset_bits = strtol(optarg, NULL, 10);
				block_size = 1 << offset_bits;
				break;
			case '?':

			default:
				usage(argv[0]);
				exit(1);
		}
	} 

	if (verbose_mode) {
		printf("Verbose mode enabled.\n");
		printf("Trace filename: %s\n", trace_filename);
		printf("Number of sets: %d\n", num_sets);
	}

	simulateCache(trace_filename, num_sets, block_size, lines_per_set, verbose_mode);
	
    return 0;
}

/**
 * Simulates cache with the specified organization (S, E, B) on the given
 * trace file.
 *
 * @param trace_file Name of the file with the memory addresses.
 * @param num_sets Number of sets in the simulator cache.
 * @param block_size Number of bytes in each cache block.
 * @param lines_per_set Number of lines in each cache set.
 * @param verbose Whether to print out extra information about what the
 *   simulator is doing (1 = yes, 0 = no).
 */
void simulateCache(char *trace_file, int num_sets, int block_size, 
						int lines_per_set, int verbose) {
	// Variables to track how many hits, misses, and evictions we've had so
	// far during simulation.
	int hit_count = 0;
	int miss_count = 0;
	int eviction_count = 0;
	
	FILE *ifp;
	char *mode = "r";
	ifp = fopen(trace_file, mode);
	if(ifp == NULL)
	{
		printf("cannot open %s \n", trace_file);
		exit(1);
	}
	//variables to be read in from file line
	char operation[2];
	mem_addr address;
	int size = 0;
	//tracking address and set, tag, and line 
	int cur_set = 0;
	int cur_tag = 0;
	int cur_line = 0;
	
	Cache cache;
	// initialize cache method
	initCache(&cache, num_sets, lines_per_set);
	// find set and offset bits
	int set_bits = log(num_sets) / log(2);
	int offset_bits = log(block_size) / log(2);
	
	// read file by line
	while( fscanf(ifp, "%s %lx,%d", operation, &address, &size) == 3)
	{
		// unpack the address to find set bits, offset bits, and current set
		// and tag values
		unpack(address, set_bits, offset_bits, &cur_set, &cur_tag);
		if(strncmp(operation, "L", 1) == 0 || strncmp(operation, "S", 1) == 0)
		{
			dataAccess(&cache, address, operation, size, verbose, &hit_count, &miss_count, &eviction_count, cur_set, cur_tag, &cur_line);
		}
		//can result in two cache hits (if the data was in cache), OR a miss
		//and a hit plus a possible eviction.
		else if(strncmp(operation, "M", 1) == 0)
		{
			dataAccess(&cache, address, operation, size, verbose, &hit_count, &miss_count, &eviction_count, cur_set, cur_tag, &cur_line);
			dataAccess(&cache, address, operation, size, verbose, &hit_count, &miss_count, &eviction_count, cur_set, cur_tag, &cur_line);
		}
		else // "I"
			continue;
	}

    printSummary(hit_count, miss_count, eviction_count);
	freeCache(&cache); // free memory allocated for cache
}

/*
 * Accesses the cache and handles a data load, data store, or data modify by:
 *     first, checking if the data is in the cache
 *     second, if a miss, check if there needs to be an eviction or not
 * 
 * @param cache is a struct that holds the data in sets 
 * @param addr is the 64-bit hexadecimal memory address
 * @param oper denotes the type of memory access: a Load, Store, or Modify data operation
 * @param size is the number of bytes accessed by the operation
 * @param verbose indicates whether the the trace info is displayed or not
 * @param hit_count keeps track of the number of times there is a hit
 * @param miss_count keeps track of the number of times there is a miss
 * @param evic_count keeps track of the number of times there is an eviction
 * @param set indicates the set bits from the address and is to be matched in isinCache method
 * @param tag indicates the tag bits from the address and is to be matched in isinCache method
 * @param line is the line number the data is on in the cache
 *
 */
void dataAccess(Cache *cache, mem_addr addr, char *oper, int size, int verbose, int *hit_count, int *miss_count, int *evic_count, int set, int tag, int *line)
{
	int result = 0;
	int evic = 0;
	result = isinCache(cache, addr, set, tag, line);
	if(result == 1) // if a hit
	{
		updateLRU(cache, set, *line);
		(*hit_count)++;
		if(verbose == 1)
		{
			printf("%s %lx,%d ", oper, addr, size);
			printf("hit \n");
		}
	}
	else // if a miss
	{
		(*miss_count)++;
		evic = updateCache(cache, set, tag, addr);
		(*evic_count) += evic;
		if(verbose == 1)
		{
			printf("%s %lx,%d ", oper, addr, size);
			if(evic == 1)
				printf("miss eviction \n");
			else
				printf("miss \n");
		}
	}
}

/*
 * Initializes the cache by allocating appropriate memory taking in the number
 * of sets and number of lines per set
 *
 * @param cache is the struct that holds the data lines
 * @param num_sets is the number of sets in the simulated cache
 * @param lines_per_set is the number of lines in a cache set
 *
 */
void initCache(Cache *cache, int num_sets, int lines_per_set)
{
	cache->num_sets = num_sets;
	cache->Sets = calloc(num_sets, sizeof(Set));

	for(int i = 0; i < cache->num_sets; i++)
	{
		cache->Sets[i].num_lines = lines_per_set;
		cache->Sets[i].lines = calloc(lines_per_set, sizeof(Line));

		// set lru for all lines in the set
		for(int j = 0; j < cache->Sets[j].num_lines; j++)
		{
				cache->Sets[i].lines[j].lru = j;
		}
	}
}

/*
 * Frees the allocated memory for the cache
 *
 * @param cache is the simulated cache struct
 *
 */
void freeCache(Cache *cache)
{
	for(int i = 0; i < cache->num_sets; i++)
	{
		free(cache->Sets[i].lines);
	}
	free(cache->Sets);
}

/*
 * Checks if the data at the specified address is in the cache or not by
 * first checking if the valid bit and then if the tag of the line matches the
 * tag of the address of the data to be stored
 *
 * @param cache is the simulated cache struct
 * @param address is the 64-bit hexadecimal memory address
 * @param set is the set bits from the address
 * @param tag is the tag bits from the address
 * @param line is the line the address is stored at in the simulated cache
 * @returns an integer that indicates a hit if a 1 and 0 for a miss
 */
int isinCache(Cache *cache, mem_addr address, int set, int tag, int *line)
{
	// check if the set number is not valid, return 0 for not in the cache
	if(set < 0 || set >= cache->num_sets)
		return 0;

	// look in all lines in the set
	for(int i = 0; i < cache->Sets[set].num_lines; i++)
	{
		// if the line isn't empty and the tag matches, we have a hit
		if(cache->Sets[set].lines[i].valid && cache->Sets[set].lines[i].tag == tag)
		{
			*line = i;
			return 1;
		}
	}
	// return 0 if there is no hit and didn't find it
	return 0;
}

/*
 * Updates the simulated cache to include the address at specified set number.
 * Calls updateLRU and sets the valid bit to 1 and tag bit to specified tag. 
 *
 * @param cache is the simulated cache struct
 * @param set is the set bit from the address that indicates what set should be updated
 * @param tag is the tag bits from the address that will be inputted 
 * @param address is the 64-bit hexadecimal memory address
 * @returns evic which indicates there was an eviction if 1 is returned and
 * there was no eviction if 0 is returned
 */
int updateCache(Cache *cache, int set, int tag, mem_addr address)
{
	int _lru = 0;
	int index = 0;
	int evic = 0;
	for(int i = 0; i < cache->Sets[set].num_lines; i++)
	{
		if(_lru < cache->Sets[set].lines[i].lru)
		{
			_lru = cache->Sets[set].lines[i].lru;
			index = i;
		}

	}
	updateLRU(cache, set, index);
	// found biggest index (LRU) -- update line
	// keep track if there is an eviction
	if(cache->Sets[set].lines[index].valid == 1)
		evic = 1;

	// update valid bit
	cache->Sets[set].lines[index].valid = 1;
	// update tag bit
	cache->Sets[set].lines[index].tag = tag;
	return evic;
}

/*
 * Updates the LRU values in the simulated cache, setting the most recently
 * accessed line's LRU to 0 and incrementing the other lines in the set's LRU
 * values by 1
 *
 * @param cache is the simulated cache struct
 * @param set is the set that the LRU's are being updated and accessed
 * @param line is the line number that was most recently used
 *
 */
void updateLRU(Cache *cache, int set, int line)
{
	cache->Sets[set].lines[line].lru = 0;
	for(int i = 0; i < cache->Sets[set].num_lines; i++)
	{
		if(i != line)
		{
			cache->Sets[set].lines[i].lru++;
		}
	}
}

/*
 * Unpacks the address specified and finds the set and tag values.
 *
 * @param address is the 64-bit hexadecimal memory address read in
 * @param set_bits is the specified set bits by user
 * @param offset_bits is the specified offset bits by the user
 * @param set is the set bits of the address
 * @param tag is the tag bits of the address
 *
 */
void unpack(mem_addr address, int set_bits, int offset_bits, int *set, int *tag)
{
	unsigned int addr = address;
	unsigned int _tag = addr >> (set_bits + offset_bits);
	unsigned int set_mask = (1 << set_bits) -1;
	unsigned int addr_shift = addr >> offset_bits;
	unsigned int _set = set_mask & addr_shift;	
	*set = _set;
	*tag = _tag;
}

