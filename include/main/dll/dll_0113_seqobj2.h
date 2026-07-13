#ifndef MAIN_DLL_DLL_0113_SEQOBJ2_H_
#define MAIN_DLL_DLL_0113_SEQOBJ2_H_

#include "main/object_descriptor.h"
#include "main/objanim_update.h"

struct SeqObjectPlacement;

typedef struct SeqObj2State
{
    u8 flags;
} SeqObj2State;

extern ObjectDescriptor gSeqObj2ObjDescriptor;

int SeqObj2_seqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate);
int SeqObj2_getExtraSize(void);
int SeqObj2_getObjectTypeId(void);
void SeqObj2_free(int obj);
void SeqObj2_render(void);
void SeqObj2_hitDetect(void);
void SeqObj2_update(int* obj);
void SeqObj2_init(int* obj, struct SeqObjectPlacement* def);
void SeqObj2_release(void);
void SeqObj2_initialise(void);

#endif /* MAIN_DLL_DLL_0113_SEQOBJ2_H_ */
