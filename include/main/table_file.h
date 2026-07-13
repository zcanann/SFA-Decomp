#ifndef MAIN_TABLE_FILE_H_
#define MAIN_TABLE_FILE_H_

#include "types.h"

u32 loadTableFiles(void);
int getTableFileEntry(int fileId, int index, int* outOffset);

#endif /* MAIN_TABLE_FILE_H_ */
