#ifndef MAIN_TEXTBLOCK_H_
#define MAIN_TEXTBLOCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern char sTextBlockInitNoLongerSupported[];
extern char sTextBlockObjInitNoLongerSupported[];
extern ObjectDescriptor gTextBlockObjDescriptor;

int textblockObj_getExtraSize(void);
int textblockObj_func08(void);
void textblockObj_freeUnsupported(void);
void textblockObj_render(void);
void textblockObj_hitDetect(void);
void textblockObj_updateUnsupported(void);
void textblockObj_init(void);
void textblockObj_release(void);
void textblockObj_initialise(void);

#endif /* MAIN_TEXTBLOCK_H_ */
