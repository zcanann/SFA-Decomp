#include "ghidra_import.h"
#include "main/dll/baddie/chuka.h"

extern undefined4* lbl_803DCA78;
extern u8 gChukaModeTable[9];
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;
extern int return0_80205F40(void);

typedef struct ChukaState {
    f32 startY;
    int linkedObject;
    u8 modeIndex;
} ChukaState;

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
#pragma scheduling off
#pragma peephole off
void chuka_init(int obj, int params)
{
    ChukaState *state = *(ChukaState **)(obj + 0xb8);
    u8 *modeTable;

    *(s16 *)(obj + 0x0) = (s16)((s8)*(u8 *)(params + 0x18) << 8);
    *(int *)(obj + 0xbc) = (int)&return0_80205F40;
    state->startY = *(f32 *)(obj + 0x10);
    state->modeIndex = *(u8 *)(params + 0x19);

    if (*(s16 *)(params + 0x1c) != 0) {
        *(f32 *)(obj + 0x8) =
            lbl_803E63F8 / ((f32)(s32)*(s16 *)(params + 0x1c) / lbl_803E63FC);
    }

    if (*(s16 *)(params + 0x1a) != 0) {
        *(s16 *)(obj + 0x4) = *(s16 *)(params + 0x1a);
    }

    *(u16 *)(obj + 0xb0) |= 0x4000;
    state->linkedObject = 0;

    modeTable = gChukaModeTable;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0; modeTable++;
    *modeTable = 0;
}
#pragma peephole reset
#pragma scheduling reset

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
typedef void (*DfpFloorbarFreeFn)(void *obj);

#pragma scheduling off
#pragma peephole off
void dfpfloorbar_free(int *obj)
{
  int *extra;

  extra = (int *)obj[0x2e];
  ((DfpFloorbarFreeFn)(*(u32 *)(*lbl_803DCA78 + 0x18)))(obj);
  extra[2] = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */
int fn_80206474(void) { return 0; }

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */
int dfpfloorbar_func08(void) { return 0; }

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
#pragma peephole off
void dfpfloorbar_render(int p1, int p2, int p3, int p4, int p5, s8 p6)
{
    s32 t = p6;
    if (t != 0) {
        objRenderFn_8003b8f4(lbl_803E6408);
    }
}
#pragma peephole reset

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
#pragma scheduling off
#pragma peephole off
void dfpfloorbar_hitDetect(int *obj)
{
    int *x;
    int **b;
    s32 v;
    b = (int **)obj[0x2e];
    x = b[2];
    if (x == NULL) return;
    v = *(s16 *)((char *)x + 6) & 0x40;
    if (v == 0) return;
    b[2] = NULL;
}
#pragma peephole reset
#pragma scheduling reset
