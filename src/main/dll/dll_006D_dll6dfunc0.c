/*
 * dll6dfunc0 (DLL 0x6D) - shared save-game / world-progress core lib.
 *
 * Owns the gameplay save-state helpers exported through gameplay.h:
 *   - debug-cheat unlock bits (saveFileStruct_unlockCheat / isCheatUnlocked)
 *     packed into gGameplayRegisteredDebugOptions.
 *   - preview color/volume defaults (saveFileStruct_resetVolumes, 0x7f each).
 *   - the save-settings apply path (loadSaveSettings) and the per-map act /
 *     object-position fix-up (FUN_800e8630).
 *   - FUN_800e95e8: the map-act flag setter that mirrors a flag bit across the
 *     map-act table and maintains the recently-changed history ring.
 *   - FUN_800e8f58 / FUN_800e9e9c: new-game / save-slot setup, seeding the
 *     map-act table and the save block.
 *   - FUN_800ea9b8: the visited-map history ring (most-recent-first, depth 5).
 *   - dll_6D_func03: builds a 6-entry modgfx command list (the spirit/aura
 *     particle effect) and submits it via gModgfxInterface->spawnEffect.
 *
 * The map-act / flag tables live at 0x803a3f08.. and 0x80312460..; the visited
 * history ring at 0x803a3be0. Bit indices are split into (word,bit) by the
 * 0x12f flag-word base. These globals are cross-TU; only this DLL writes the
 * debug-option and preview-color globals.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

/* one modgfx draw command in the dll_6D_func03 effect list */
typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

/* Cross-TU main-lib functions and globals this DLL references (home TUs
   un-recovered; left as Ghidra FUN_/DAT_ names). */

extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006770();
extern int FUN_80006b7c();
extern u32 FUN_80006b84();
extern u32 FUN_80006b8c();
extern u32 FUN_80006c20();
extern u32 FUN_80017488();
extern u32 FUN_80017498();
extern u32 FUN_80017500();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern u32 FUN_800176cc();
extern u32 FUN_800176dc();
extern u32 FUN_80042b9c();
extern u32 FUN_8005d018();
extern u32 FUN_80072564();
extern u32 FUN_800d783c();
extern u32 FUN_8011e80c();
extern s64 FUN_80286830();
extern u32 FUN_80286834();
extern u32 FUN_8028687c();
extern u32 FUN_80286880();
extern u32 DAT_802c28f0;
extern u32 DAT_802c28f4;
extern u32 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern u32 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern u32 DAT_803a3be1;
extern u32 DAT_803a3be2;
extern u32 DAT_803a3c1c;
extern u32 DAT_803a3dac;
extern u8 gGameplayPreviewSettings;
extern u32 DAT_803a3e26;
extern u32 DAT_803a3e27;
extern u32 DAT_803a3e28;
extern u32 DAT_803a3e2a;
extern u32 DAT_803a3e2c;
extern u32 DAT_803a3e2d;
extern u32 gGameplayPreviewColorRed;
extern u32 gGameplayPreviewColorGreen;
extern u32 gGameplayPreviewColorBlue;
extern u32 gGameplayRegisteredDebugOptions;
extern u8 DAT_803a3f08;
extern u32 DAT_803a3f09;
extern u32 DAT_803a3f0c;
extern u32 DAT_803a3f0e;
extern u32 DAT_803a3f12;
extern u32 DAT_803a3f14;
extern u32 DAT_803a3f15;
extern u32 DAT_803a3f18;
extern u32 DAT_803a3f1a;
extern u32 DAT_803a3f1e;
extern u32 DAT_803a3f21;
extern char DAT_803a3f24;
extern u32 DAT_803a3f25;
extern u32 DAT_803a3f26;
extern u32 DAT_803a3f27;
extern u32 DAT_803a3f28;
extern u32 DAT_803a3f29;
extern u32 DAT_803a3f2b;
extern u32 DAT_803a4070;
extern u32 DAT_803a4074;
extern u32 DAT_803a4078;
extern u32 DAT_803a407c;
extern u32 DAT_803a4460;
extern u32 DAT_803a4465;
extern u32 DAT_803a458c;
extern u32 DAT_803a4590;
extern u32 DAT_803a4594;
extern u32 DAT_803a4599;
extern u32 DAT_803a459a;
extern u32 DAT_803a45aa;
extern u32 DAT_803a45ac;
extern u32 DAT_803a45b0;
extern u32 DAT_803a45b4;
extern u32 DAT_803a45b6;
extern u32 DAT_803a45ba;
extern u32 DAT_803a45bc;
extern u32 DAT_803a45be;
extern u32 DAT_803a45c0;
extern u32 DAT_803a45c2;
extern u32 DAT_803a45f0;
extern u32 DAT_803a45f1;
extern u32 DAT_803a45f2;
extern u32 DAT_803a45f3;
extern u32 DAT_803a4e78;
extern u32 DAT_803dc4f0;
extern u32* DAT_803dd6d0;
extern u32* DAT_803dd6e8;
extern u32 DAT_803de100;
extern u32 DAT_803de104;
extern u32 DAT_803de10c;
extern u32* DAT_803de110;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern u8 lbl_80313AF0[];
extern f32 lbl_803E0A78;
extern f32 lbl_803E0A7C;
extern f32 lbl_803E0A80;
extern f32 lbl_803E0A84;
extern f32 lbl_803E0A88;
extern f32 lbl_803E0A8C;
extern f32 lbl_803E0A90;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
}

u32 isCheatUnlocked(u32 cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                      u64 param_5, u64 param_6, u64 param_7,
                      u64 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(VtableFn**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(VtableFn**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((u32)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((u32)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((u32)gGameplayPreviewColorBlue, 10, 0, 0, 1);
}

u8* FUN_800e82d8(void)
{
    return (u8*)&DAT_803a4460;
}

void FUN_800e8630(int obj)
{
    int objId;
    u8* entry;
    int slotBase;
    int slotIdx;
    int groupsLeft;

    if ((*(u16*)&((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    slotBase = 0;
    entry = &DAT_803a3f08;
    groupsLeft = 9;
    while ((slotIdx = slotBase, *(int*)(entry + 0x168) != 0 &&
        (objId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14), objId != *(int*)(entry + 0x168))))
    {
        slotIdx = slotBase + 1;
        if ((*(int*)(entry + 0x178) == 0) || (objId == *(int*)(entry + 0x178))) break;
        slotIdx = slotBase + 2;
        if ((*(int*)(entry + 0x188) == 0) || (objId == *(int*)(entry + 0x188))) break;
        slotIdx = slotBase + 3;
        if ((*(int*)(entry + 0x198) == 0) || (objId == *(int*)(entry + 0x198))) break;
        slotIdx = slotBase + 4;
        if ((*(int*)(entry + 0x1a8) == 0) || (objId == *(int*)(entry + 0x1a8))) break;
        slotIdx = slotBase + 5;
        if ((*(int*)(entry + 0x1b8) == 0) || (objId == *(int*)(entry + 0x1b8))) break;
        slotIdx = slotBase + 6;
        if ((*(int*)(entry + 0x1c8) == 0) || (objId == *(int*)(entry + 0x1c8))) break;
        entry = entry + 0x70;
        slotBase = slotBase + 7;
        groupsLeft--;
        slotIdx = slotBase;
        if (groupsLeft == 0) break;
    }
    if (slotIdx == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[slotIdx * 4] = *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[slotIdx * 4] = *(u32*)&((GameObject*)obj)->anim.localPosZ;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = *(u32*)&((GameObject*)obj)->anim
        .localPosX;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = *(u32*)&((GameObject*)obj)->
        anim.localPosY;
    *(u32*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = *(u32*)&((GameObject*)obj)->
        anim.localPosZ;
}

u32* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

u8 FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(u64 param_1, double param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 savedX;
    u32 savedY;
    u32 savedZ;
    char* dst;
    int act;
    short* actFlags;
    char* src;
    char c;
    u64 saveHandle;
    u64 result;

    result = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    src = (char*)((u64)result >> 0x20);
    memset((void*)-0x7fc5c0f8, 0, 0xf70);
    if ((*(u8*)(DAT_803de110 + 0x21) & 0x80) == 0)
    {
        memset((void*)DAT_803de110, 0, 0x6ec);
    }
    DAT_803a3f28 = 0;
    DAT_803a3f08 = 0xc;
    DAT_803a3f09 = 0xc;
    DAT_803a3f0e = 0x19;
    DAT_803a3f0c = 0;
    DAT_803a3f12 = 1;
    DAT_803a459a = 0xff;
    DAT_803a3f14 = 0xc;
    DAT_803a3f15 = 0xc;
    DAT_803a3f1a = 0x19;
    DAT_803a3f18 = 0;
    DAT_803a3f1e = 1;
    DAT_803a45aa = 0xff;
    DAT_803a3f21 = 0x14;
    DAT_803a45ac = 0xffff;
    DAT_803a45b0 = lbl_803E1348;
    DAT_803a45b4 = 0xffff;
    DAT_803a45b6 = 0xffff;
    DAT_803a45ba = 0xffff;
    DAT_803a45bc = 0xffff;
    DAT_803a45be = 0xffff;
    DAT_803a45c0 = 0xffff;
    DAT_803a45c2 = 0xffff;
    DAT_803a45f1 = 0xff;
    DAT_803a45f2 = 0xff;
    DAT_803a45f3 = 0xff;
    DAT_803a45f0 = 9;
    DAT_803a3f2b = 0;
    DAT_803a3f29 = 1;
    act = 0;
    actFlags = &DAT_80312370;
    do
    {
        if (*actFlags != 0)
        {
            (*gMapEventInterface)->setMapAct(act, 1);
        }
        actFlags++;
        act++;
    }
    while (act < 0x78);
    FUN_800e95e8(7, 0, 1);
    FUN_800e95e8(7, 2, 1);
    FUN_800e95e8(7, 3, 1);
    FUN_800e95e8(7, 5, 1);
    FUN_800e95e8(7, 10, 1);
    FUN_800e95e8(0x1d, 0, 1);
    FUN_800e95e8(0x1d, 0x1f, 1);
    FUN_800e95e8(0x13, 0, 1);
    FUN_800e95e8(0x13, 0x16, 1);
    FUN_80017698(0x967, 1);
    (&DAT_803a458c)[DAT_803a3f28 * 4] = savedX;
    (&DAT_803a4590)[DAT_803a3f28 * 4] = savedY;
    (&DAT_803a4594)[DAT_803a3f28 * 4] = savedZ;
    DAT_803a4465 = 1;
    if (src == NULL)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        src = NULL;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            c = *src;
            src++;
            *dst = c;
            dst++;
        }
        while (c != '\0');
    }
    saveHandle = (u64)memcpy(DAT_803de110, (void*)0x803a3f08, 0x6ec);
    c = result;
    if ((c != -1) && (DAT_803dc4f0 = c, src != NULL))
    {
        FUN_80072564(saveHandle, param_2, param_3, param_4, param_5, param_6, param_7, param_8, result & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(u32 groupId, u32 flagArg, int mode)
{
    bool isClearMode;
    char foundIndex;
    u32 maskWord;
    char rowBase;
    short* idPtr;
    char* rowPtr;
    u32* flagPtr;
    u32 bit;
    u32 newMask;
    u32 actId;
    char* table;
    int i;
    int j;
    s64 rawId;

    rawId = FUN_80286830();
    actId = (u32)((u64)rawId >> 0x20);
    bit = rawId;
    table = &DAT_803a3be0;
    if (0x4fffffffff < rawId)
    {
        actId = (u32)(u8)(&DAT_803a3dac)[actId];
    }
    if ((int)actId < 0x78)
    {
        if ((u16)(&DAT_80312460)[actId] != 0)
        {
            if (mode == -1)
            {
                mode = 1;
            }
            isClearMode = mode == -2;
            if (isClearMode)
            {
                mode = 0;
            }
            maskWord = FUN_80017690((u32)(u16)(&DAT_80312460)[actId]);
            if (mode == 0)
            {
                newMask = maskWord & ~(1 << bit);
            }
            else
            {
                newMask = maskWord | 1 << bit;
            }
            FUN_80017698((u32)(u16)(&DAT_80312460)[actId], newMask);
            DAT_803de104 = actId;
            uRam803de108 = newMask;
            if (mode == 0)
            {
                idPtr = &DAT_80312460;
                flagPtr = &DAT_803a3c1c;
                maskWord = ~(1 << bit);
                i = 0x14;
                do
                {
                    if (*idPtr == (&DAT_80312460)[actId])
                    {
                        *flagPtr = *flagPtr & maskWord;
                    }
                    if (idPtr[1] == (&DAT_80312460)[actId])
                    {
                        flagPtr[1] = flagPtr[1] & maskWord;
                    }
                    if (idPtr[2] == (&DAT_80312460)[actId])
                    {
                        flagPtr[2] = flagPtr[2] & maskWord;
                    }
                    if (idPtr[3] == (&DAT_80312460)[actId])
                    {
                        flagPtr[3] = flagPtr[3] & maskWord;
                    }
                    if (idPtr[4] == (&DAT_80312460)[actId])
                    {
                        flagPtr[4] = flagPtr[4] & maskWord;
                    }
                    if (idPtr[5] == (&DAT_80312460)[actId])
                    {
                        flagPtr[5] = flagPtr[5] & maskWord;
                    }
                    idPtr = idPtr + 6;
                    flagPtr = flagPtr + 6;
                    i--;
                }
                while (i != 0);
                if (!isClearMode)
                {
                    rowBase = '\0';
                    i = 4;
                    rowPtr = table;
                    do
                    {
                        if ((((((actId == (int)*rowPtr) && (foundIndex = rowBase, bit == rowPtr[1])) ||
                                    ((foundIndex = rowBase + '\x01', actId == rowPtr[3] && (bit == rowPtr[4])))
                                ) || ((foundIndex = rowBase + '\x02', actId == rowPtr[6] &&
                                    (bit == rowPtr[7])))) ||
                                ((foundIndex = rowBase + '\x03', actId == rowPtr[9] && (bit == rowPtr[10]))))
                            || ((actId == rowPtr[0xc] &&
                                (foundIndex = rowBase + '\x04', bit == rowPtr[0xd]))))
                            goto LAB_800e9628;
                        rowPtr = rowPtr + 0xf;
                        rowBase = rowBase + '\x05';
                        i--;
                    }
                    while (i != 0);
                    foundIndex = -1;
                LAB_800e9628:
                    if (foundIndex == -1)
                    {
                        i = 0;
                        j = 0x14;
                        do
                        {
                            if (*table == -1)
                            {
                                i = i * 3;
                                (&DAT_803a3be0)[i] = actId;
                                (&DAT_803a3be1)[i] = rawId;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            table = table + 3;
                            i++;
                            j--;
                        }
                        while (j != 0);
                    }
                }
            }
            else
            {
                bit = 1 << bit;
                if ((maskWord & bit) == 0)
                {
                    idPtr = &DAT_80312460;
                    flagPtr = &DAT_803a3c1c;
                    i = 0x14;
                    do
                    {
                        if (*idPtr == (&DAT_80312460)[actId])
                        {
                            *flagPtr = *flagPtr | bit;
                        }
                        if (idPtr[1] == (&DAT_80312460)[actId])
                        {
                            flagPtr[1] = flagPtr[1] | bit;
                        }
                        if (idPtr[2] == (&DAT_80312460)[actId])
                        {
                            flagPtr[2] = flagPtr[2] | bit;
                        }
                        if (idPtr[3] == (&DAT_80312460)[actId])
                        {
                            flagPtr[3] = flagPtr[3] | bit;
                        }
                        if (idPtr[4] == (&DAT_80312460)[actId])
                        {
                            flagPtr[4] = flagPtr[4] | bit;
                        }
                        if (idPtr[5] == (&DAT_80312460)[actId])
                        {
                            flagPtr[5] = flagPtr[5] | bit;
                        }
                        idPtr = idPtr + 6;
                        flagPtr = flagPtr + 6;
                        i = i + -1;
                    }
                    while (i != 0);
                }
            }
        }
    }
    FUN_8028687c();
}

void FUN_800e9e9c(void)
{
    u32 slotIdx;
    int saveResult;
    u32 extraout_r4;
    u32 sizeArg;
    u32 in_r6;
    u32 in_r7;
    u32 in_r8;
    u32 in_r9;
    u32 in_r10;
    u64 in_f4;
    u64 in_f5;
    u64 in_f6;
    u64 in_f7;
    u64 in_f8;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    sizeArg = 0x884;
    memset((void*)-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    slotIdx = DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[slotIdx * 4], (double)(float)(&DAT_803a4590)[slotIdx * 4],
                 (double)(float)(&DAT_803a4594)[slotIdx * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[slotIdx * 0x10], extraout_r4, sizeArg, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    saveResult = FUN_80006b7c();
    if (saveResult != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}

u32
FUN_800ea8c8(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
    u32 result;
    u8* history;

    result = FUN_80017498();
    history = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (u32)(u8)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (u32)(u8)history[5] * 2)
    ]
    )
    ;
    return result;
}

u8 FUN_800ea9ac(void)
{
    u8* history;

    history = FUN_800e82d8();
    return history[5];
}

void FUN_800ea9b8(void)
{
    u32 id;
    u8* hist;
    short i;
    u32 mask;
    u32 bit;
    u32 wordId;
    u32 cachedMask;
    u32 lastWordId;
    u32 scanId;
    short* idPtr;

    id = FUN_80286834();
    hist = FUN_800e82d8();
    lastWordId = 0xffffffff;
    if (hist[6] == '\0')
    {
        idPtr = &DAT_80312632;
        for (scanId = 1; scanId < 0xce; scanId = scanId + 1)
        {
            if ((*idPtr == 0xffff) || (*idPtr == -1))
            {
                bit = 1 << (scanId & 0x1f);
                wordId = (u32)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
                mask = FUN_80017690(wordId);
                if ((mask & bit) == 0)
                {
                    FUN_80017698(wordId, mask | bit);
                }
            }
            idPtr = idPtr + 1;
        }
    }
    wordId = 1 << (id & 0x1f);
    mask = (u32)(short)((short)((id & 0xff) >> 5) + 0x12f);
    scanId = FUN_80017690(mask);
    if ((scanId & wordId) == 0)
    {
        FUN_80017698(mask, scanId | wordId);
        if (hist[6] != '\x05')
        {
            hist[6] = hist[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            hist[i] = hist[i + -1];
        }
        *hist = id;
        if ((u32)(u8)hist[5] == (id & 0xff)
        )
        {
            do
            {
                hist[5] = hist[5] + '\x01';
                id = (u32)(short)(((u8)hist[5] >> 5) + 0x12f);
                if (id != (int)(short)lastWordId)
                {
                    cachedMask = FUN_80017690(id);
                    lastWordId = id;
                }
            }
            while ((cachedMask & 1 << ((u8)hist[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
}

void SaveGame_func08_nop(void);

void dll_6D_func01_nop(void)
{
}

void dll_6D_func00_nop(void)
{
}

void dll_6E_func01_nop(void);

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void dll_6D_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80313AF0;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0xe;
    buf.entries[0].tex = &base[212];
    buf.entries[0].mode = 0x80;
    buf.entries[0].x = lbl_803E0A78;
    buf.entries[0].y = lbl_803E0A7C;
    buf.entries[0].z = lbl_803E0A78;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 7;
    buf.entries[1].tex = &base[256];
    buf.entries[1].mode = 4;
    buf.entries[1].x = lbl_803E0A78;
    buf.entries[1].y = lbl_803E0A78;
    buf.entries[1].z = lbl_803E0A78;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[240];
    buf.entries[2].mode = 2;
    buf.entries[2].x = (*(f32*)&lbl_803E0A80);
    buf.entries[2].y = (*(f32*)&lbl_803E0A84);
    buf.entries[2].z = (*(f32*)&lbl_803E0A80);
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[256];
    buf.entries[3].mode = 2;
    buf.entries[3].x = (*(f32*)&lbl_803E0A88);
    buf.entries[3].y = (*(f32*)&lbl_803E0A84);
    buf.entries[3].z = (*(f32*)&lbl_803E0A88);
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0xe;
    buf.entries[4].tex = &base[212];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = lbl_803E0A78;
    buf.entries[4].y = lbl_803E0A8C;
    buf.entries[4].z = lbl_803E0A78;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[240];
    buf.entries[5].mode = 4;
    buf.entries[5].x = lbl_803E0A78;
    buf.entries[5].y = lbl_803E0A78;
    buf.entries[5].z = lbl_803E0A78;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A78;
    buf.pos[1] = lbl_803E0A78;
    buf.pos[2] = lbl_803E0A78;
    buf.col[0] = lbl_803E0A78;
    buf.col[1] = lbl_803E0A78;
    buf.col[2] = lbl_803E0A78;
    buf.scale = lbl_803E0A90;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[272];
    buf.hw[1] = *(s16*)&base[274];
    buf.hw[2] = *(s16*)&base[276];
    buf.hw[3] = *(s16*)&base[278];
    buf.hw[4] = *(s16*)&base[280];
    buf.hw[5] = *(s16*)&base[282];
    buf.hw[6] = *(s16*)&base[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000004;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0A78 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0A78 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0A78 + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80313AF0, 0xc, &base[140], 0x34, 0);
}

void dll_6E_func03(int sourceObj, int variant, int posSource, u32 flags);
