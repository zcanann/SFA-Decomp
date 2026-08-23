#ifndef MAIN_LOADED_FILE_FLAGS_H_
#define MAIN_LOADED_FILE_FLAGS_H_

#define LOADED_FILE_FLAG_PI_LOCKED 0x100000

int getLoadedFileFlags(int slot);
void setLoadedFileFlags_blocks1(void);
void clearLoadedFileFlags_blocks1(void);
void* getCurrentDataFile(int id);

#endif /* MAIN_LOADED_FILE_FLAGS_H_ */
