#ifndef MAIN_DLL_DLL_00EC_INFOPOINT_H_
#define MAIN_DLL_DLL_00EC_INFOPOINT_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

struct GameTextDef;

typedef struct InfoPointState
{
    struct GameTextDef* text;
    char* firstString;
    int* renderData;
    s32 timer;       /* 0x0C: scroll/fade timer (starts at 100) */
    u8 unk10;        /* 0x10: copied from placement->unk1B */
    u8 pad11[0x16 - 0x11];
    s16 eventState;  /* 0x16: toggled 0xff/0 by InfoPoint_SeqFn events 1/2 */
    int unk18;       /* 0x18: starts at 2 */
    u8 pad1C[0x20 - 0x1C];
} InfoPointState;

typedef struct InfoPointPlacement
{
    ObjPlacement base;
    u16 textId; /* 0x18: game-text id passed to gameTextGet */
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    u8 rotXByte; /* 0x1C: rotX in 1/256 turns (<< 8 into anim.rotX) */
    u8 pad1D;
    u8 unk1E;
    u8 unk1F;
} InfoPointPlacement;

STATIC_ASSERT(sizeof(InfoPointState) == 0x20);
STATIC_ASSERT(offsetof(InfoPointState, text) == 0x0);
STATIC_ASSERT(offsetof(InfoPointState, timer) == 0xC);
STATIC_ASSERT(offsetof(InfoPointState, eventState) == 0x16);
STATIC_ASSERT(offsetof(InfoPointState, unk18) == 0x18);
STATIC_ASSERT(sizeof(InfoPointPlacement) == 0x20);
STATIC_ASSERT(offsetof(InfoPointPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(InfoPointPlacement, textId) == 0x18);
STATIC_ASSERT(offsetof(InfoPointPlacement, unk1B) == 0x1B);
STATIC_ASSERT(offsetof(InfoPointPlacement, rotXByte) == 0x1C);

int InfoPoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int InfoPoint_getExtraSize(void);
int InfoPoint_getObjectTypeId(void);
void InfoPoint_free(void);
void InfoPoint_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void InfoPoint_hitDetect(void);
void InfoPoint_update(GameObject* obj);
void InfoPoint_init(GameObject* obj, InfoPointPlacement* placement);
void InfoPoint_release(void);
void InfoPoint_initialise(void);

#endif /* MAIN_DLL_DLL_00EC_INFOPOINT_H_ */
