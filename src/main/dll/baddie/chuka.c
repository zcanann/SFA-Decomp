#include "main/dll/baddie/chuka.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/baddie/chukachuck.h"

extern u8 gChukaModeTable[9];
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;

/*
 * --INFO--
 *
 * Function: chuka_init
 * EN v1.0 Address: 0x8020637C
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80206444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_init(int obj, int params)
{
    ChukaState* state = ((GameObject*)obj)->extra;
    u8* modeTable;

    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(params + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)chuka_SeqFn;
    state->startY = ((GameObject*)obj)->anim.localPosY;
    state->modeIndex = *(u8*)(params + 0x19);

    if (*(s16*)(params + 0x1c) != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            lbl_803E63F8 / ((f32)(s32) * (s16*)(params + 0x1c) / lbl_803E63FC);
    }

    if (*(s16*)(params + 0x1a) != 0)
    {
        ((GameObject*)obj)->anim.rotZ = *(s16*)(params + 0x1a);
    }

    ((GameObject*)obj)->objectFlags |= 0x4000;
    state->linkedObject = 0;

    modeTable = gChukaModeTable;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
    modeTable++;
    *modeTable = 0;
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_free
 * EN v1.0 Address: 0x80206480
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80206590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_free(int* obj)
{
    DfpFloorbarState* state;

    state = (DfpFloorbarState*)*(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    state->linkedObject = NULL;
    return;
}

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */
int dfpfloorbar_SeqFn(void) { return 0; }

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */
int dfpfloorbar_getObjectTypeId(void) { return 0; }

/*
 * --INFO--
 *
 * Function: chuka_release
 * EN v1.0 Address: 0x8020646C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_release(void)
{
}

/*
 * --INFO--
 *
 * Function: chuka_initialise
 * EN v1.0 Address: 0x80206470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_getExtraSize
 * EN v1.0 Address: 0x8020647C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfpfloorbar_getExtraSize(void)
{
    return 0xc;
}

extern f32 lbl_803E6408;
extern void objRenderFn_8003b8f4(f32);

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */
void dfpfloorbar_render(int p1, int p2, int p3, int p4, int p5, s8 p6)
{
    s32 t = p6;
    if (t != 0)
    {
        objRenderFn_8003b8f4(lbl_803E6408);
    }
}

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
void dfpfloorbar_hitDetect(int* obj)
{
    int* x;
    int** b;
    s32 v;
    b = (int**)*(int*)&((GameObject*)obj)->extra;
    x = b[2];
    if (x == NULL) return;
    v = *(s16*)((char*)x + 6) & 0x40;
    if (v == 0) return;
    b[2] = NULL;
}
