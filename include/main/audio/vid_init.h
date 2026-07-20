#ifndef MAIN_AUDIO_VID_INIT_H_
#define MAIN_AUDIO_VID_INIT_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

extern McmdVidListNode vidListNodes[128];
extern u32 vidCurrentId;
extern McmdVidListNode* vidRoot;
extern McmdVidListNode* vidFree;

void vidInit(void);

#endif /* MAIN_AUDIO_VID_INIT_H_ */
