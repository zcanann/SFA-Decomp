#ifndef MAIN_OBJLIB_API_H_
#define MAIN_OBJLIB_API_H_

#include "global.h"

typedef struct ObjLookAtControlFlags
{
    u8 flip : 1;
    u8 rest : 7;
} ObjLookAtControlFlags;

extern ObjLookAtControlFlags gObjLookAtControlFlags;

void objSetLookAtFlip(int mode, u8 enabled);

#endif /* MAIN_OBJLIB_API_H_ */
