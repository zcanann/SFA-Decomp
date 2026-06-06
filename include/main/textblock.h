#ifndef MAIN_TEXTBLOCK_H_
#define MAIN_TEXTBLOCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define TEXTBLOCK_DLL_ID 0x0239
#define TEXTBLOCK_OBJECT_CLASS_ID 0x0030
#define TEXTBLOCK_OBJECT_DEF_KP_TEXTBLOC_0 0x02C8
#define TEXTBLOCK_OBJECT_DEF_KP_TEXTBLOC_1 0x02C9
#define TEXTBLOCK_OBJECT_DEF_KP_TEXTBLOC_2 0x02CA
#define TEXTBLOCK_OBJECT_DEF_KP_TEXTBLOC_3 0x02CB
#define TEXTBLOCK_OBJECT_DEF_DFP_TEXTBLO 0x0371

extern char sTextBlockInitNoLongerSupported[];
extern char sTextBlockObjInitNoLongerSupported[];
extern ObjectDescriptor gTextBlockObjDescriptor;

int textblockObj_getExtraSize(void);
int textblockObj_getObjectTypeId(void);
void textblockObj_freeUnsupported(void);
void textblockObj_render(void);
void textblockObj_hitDetect(void);
void textblockObj_updateUnsupported(void);
void textblockObj_init(void);
void textblockObj_release(void);
void textblockObj_initialise(void);

#endif /* MAIN_TEXTBLOCK_H_ */
