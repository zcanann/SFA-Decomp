#ifndef MAIN_DLL_DLL_0126_TRIGGER_API_H_
#define MAIN_DLL_DLL_0126_TRIGGER_API_H_

#include "global.h"

struct GameObject;

#ifdef DLL_0126_TRIGGER_LEGCODE_INT
void objInterpretSeq(struct GameObject* obj, struct GameObject* seqObj, int legCode, int distSq);
#else
void objInterpretSeq(struct GameObject* obj, struct GameObject* seqObj, s8 legCode, int distSq);
#endif

#endif /* MAIN_DLL_DLL_0126_TRIGGER_API_H_ */
