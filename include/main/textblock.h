#ifndef MAIN_TEXTBLOCK_H_
#define MAIN_TEXTBLOCK_H_

#include "ghidra_import.h"

extern char sTextBlockInitNoLongerSupported[];
extern char sTextBlockNoLongerSupported[];

int textblockObj_getExtraSize(void);
int textblockObj_func08(void);
void textblockObj_freeUnsupported(void);
void textblockObj_render(void);
void textblockObj_hitDetect(void);
void textblockObj_updateUnsupported(void);
void textblockObj_initUnsupported(void);
void textblockObj_release(void);
void textblockObj_initialise(void);

#endif /* MAIN_TEXTBLOCK_H_ */
