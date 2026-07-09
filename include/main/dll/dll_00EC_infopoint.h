#ifndef MAIN_DLL_DLL_00EC_INFOPOINT_H_
#define MAIN_DLL_DLL_00EC_INFOPOINT_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

typedef struct InfopointObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 textId; /* 0x18: game-text id passed to gameTextGet */
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    u8 rotXByte; /* 0x1C: rotX in 1/256 turns (<< 8 into anim.rotX) */
    u8 pad1D;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;

int InfoPoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int InfoPoint_getExtraSize(void);
int InfoPoint_getObjectTypeId(void);
void InfoPoint_free(void);
void InfoPoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void InfoPoint_hitDetect(void);
void InfoPoint_update(GameObject* obj);
void InfoPoint_init(int* obj, u8* def);
void InfoPoint_release(void);
void InfoPoint_initialise(void);

#endif /* MAIN_DLL_DLL_00EC_INFOPOINT_H_ */
