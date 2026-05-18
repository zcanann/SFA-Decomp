#include "ghidra_import.h"
#include "main/dll/baddie/chuka.h"
#include "main/dll/baddie/chukachuck.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern u8 *Obj_GetPlayerObject(void);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);

extern void fn_80206474(void);

u8 gDfpfloorbarModeTable[12] = {
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
};
extern undefined4 *lbl_803DCAAC;
extern f32 timeDelta;
extern f32 lbl_803E6408;
extern f32 lbl_803E640C;
extern f32 lbl_803E6410;
extern f32 lbl_803E6414;
extern f32 lbl_803E6418;
extern f32 lbl_803E641C;
extern f32 lbl_803E6420;
extern f32 lbl_803E6424;
extern f32 lbl_803E6428;
extern f32 lbl_803E642C;

/*
 * --INFO--
 *
 * Function: dfpfloorbar_update
 * EN v1.0 Address: 0x8020652C
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x802065F0
 * EN v1.1 Size: 964b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfpfloorbar_update(int param_1)
{
    int iVar6 = *(int *)(param_1 + 0x4c);
    DfpFloorbarState *state = *(DfpFloorbarState **)(param_1 + 0xb8);
    s16 score = -1;
    int mode;
    u8 active;
    u32 r27;
    u8 *playerObj;
    f32 yDelta;
    f32 xMid;
    f32 zDelta;

    mode = *(s8 *)(param_1 + 0xac);
    mode = (*(code *)(*lbl_803DCAAC + 0x40))(mode);

    switch ((u8)mode) {
        case 1:
            if (state->modeIndex > 5) return;
            if (GameBit_Get(0xe57) != 0) {
                *(f32 *)(param_1 + 0x10) = *(f32 *)(iVar6 + 0xc) - lbl_803E640C;
                return;
            }
            break;
        case 2:
            if (GameBit_Get(0xe58) != 0) {
                *(f32 *)(param_1 + 0x10) = *(f32 *)(iVar6 + 0xc) - lbl_803E640C;
                return;
            }
            break;
    }

    r27 = (u8)GameBit_Get(0x5e4);
    if (GameBit_Get(0x5e5) != 0 || r27 != state->lastSequenceValue) {
        state->active = 0;
    }
    state->lastSequenceValue = (u8)r27;

    if (state->linkedObject == NULL) {
        int *items;
        int idx_init;
        int count;
        int idx;
        items = ObjList_GetObjects(&idx_init, &count);
        idx = idx_init;
        for (; idx < count; idx++) {
            int o = items[idx];
            if (*(s16 *)(o + 0x46) == 0x431) {
                state->linkedObject = (int *)o;
                idx = count;
            }
        }
        if (state->linkedObject == NULL) return;
    }

    {
        int objPtr = (int)state->linkedObject;
        (*(code *)(**(int **)(objPtr + 0x68) + 0x20))(objPtr, gDfpfloorbarModeTable);
    }

    state->requiredScore = gDfpfloorbarModeTable[state->modeIndex];

    active = state->active;
    if (active != 0) {
        if (*(f32 *)(param_1 + 0x10) > *(f32 *)(iVar6 + 0xc) - lbl_803E640C) {
            Sfx_KeepAliveLoopedObjectSound(param_1, 0x1c8);
            *(f32 *)(param_1 + 0x10) = *(f32 *)(param_1 + 0x10) - timeDelta / lbl_803E6410;
            if (*(f32 *)(param_1 + 0x10) <= *(f32 *)(iVar6 + 0xc) - lbl_803E640C) {
                *(f32 *)(param_1 + 0x10) = *(f32 *)(iVar6 + 0xc) - lbl_803E640C;
            }
        }
        return;
    }

    if (state->requiredScore == 0) return;
    if (active == 0) {
        *(f32 *)(param_1 + 0x10) = *(f32 *)(iVar6 + 0xc);
    }
    if (state->active != 0) return;

    playerObj = Obj_GetPlayerObject();
    if (playerObj == NULL) return;

    yDelta = *(f32 *)(param_1 + 0x10) - *(f32 *)(playerObj + 0x10);
    if (yDelta < lbl_803E6418) yDelta = yDelta * lbl_803E6414;
    if (yDelta >= lbl_803E641C) return;

    xMid = *(f32 *)(playerObj + 0xc) - (*(f32 *)(param_1 + 0xc) - lbl_803E641C);
    zDelta = *(f32 *)(param_1 + 0x14) - *(f32 *)(playerObj + 0x14);
    if (zDelta < lbl_803E6418) zDelta = zDelta * lbl_803E6414;
    if (zDelta >= lbl_803E6420) return;

    if (xMid >= lbl_803E6424) {
        score = 4;
    } else if (xMid >= lbl_803E641C) {
        score = 3;
    } else if (xMid >= lbl_803E6428) {
        score = 2;
    } else if (xMid >= lbl_803E6418) {
        score = 1;
    }

    if ((s16)score == (s16)state->requiredScore) {
        state->active = 1;
        return;
    }

    GameBit_Set(0x5e5, 1);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfpfloorbar_release
 * EN v1.0 Address: 0x80206928
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_init
 * EN v1.0 Address: 0x80206844
 * EN v1.0 Size: 228b
 */
#pragma scheduling off
#pragma peephole off
void dfpfloorbar_init(int obj, int params)
{
    DfpFloorbarState *state = *(DfpFloorbarState **)(obj + 0xb8);

    *(s16 *)(obj + 0x0) = (s16)((s8)*(u8 *)(params + 0x18) << 8);
    *(int *)(obj + 0xbc) = (int)&fn_80206474;
    state->modeIndex = *(u8 *)(params + 0x19);
    state->triggerGameBit = *(s16 *)(params + 0x1e);
    state->completionGameBit = *(s16 *)(params + 0x20);
    state->linkedObject = NULL;

    if (*(s16 *)(params + 0x1c) != 0) {
        *(f32 *)(obj + 0x8) = lbl_803E6408 / ((f32)(s32)*(s16 *)(params + 0x1c) / lbl_803E642C);
    }

    if (GameBit_Get((int)state->completionGameBit) != 0) {
        state->active = 1;
        *(f32 *)(obj + 0x10) = *(f32 *)(params + 0xc) - lbl_803E640C;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8020692C  size: 60b  Zero out the 9-byte mode table by
 * walking three rows of 3 bytes each. The asm has explicit
 * `addi r3, r3, 3` pointer-bump between rows. MWCC -O4,p folds the
 * stride into a flat 9-store sequence regardless of source idiom;
 * the row-pointer cast at least gets the prologue and first row
 * matching. */
#pragma scheduling off
#pragma peephole off
void dfpfloorbar_initialise(void)
{
    u8 (*p)[3] = (u8 (*)[3])gDfpfloorbarModeTable;
    (*p)[0] = 0; (*p)[1] = 0; (*p)[2] = 0;
    p++;
    (*p)[0] = 0; (*p)[1] = 0; (*p)[2] = 0;
    p++;
    (*p)[0] = 0; (*p)[1] = 0; (*p)[2] = 0;
}
#pragma peephole reset
#pragma scheduling reset

ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dfpfloorbar_initialise,
        (ObjectDescriptorCallback)dfpfloorbar_release,
        0,
        (ObjectDescriptorCallback)dfpfloorbar_init,
        (ObjectDescriptorCallback)dfpfloorbar_update,
        (ObjectDescriptorCallback)dfpfloorbar_hitDetect,
        (ObjectDescriptorCallback)dfpfloorbar_render,
        (ObjectDescriptorCallback)dfpfloorbar_free,
        (ObjectDescriptorCallback)dfpfloorbar_func08,
        dfpfloorbar_getExtraSize,
    },
    0,
};
