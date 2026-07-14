#ifndef MAIN_PI_DATA_FILE_API_H_
#define MAIN_PI_DATA_FILE_API_H_

void loadDataFiles(int arg);

#define loadDataFilesNoArgLegacy() \
    (((void (*)(void))loadDataFiles)())

#endif /* MAIN_PI_DATA_FILE_API_H_ */
