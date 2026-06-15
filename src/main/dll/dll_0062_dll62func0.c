#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006770();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b8c();
extern undefined4 FUN_80006c20();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern undefined4 FUN_80017500();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176cc();
extern undefined4 FUN_800176dc();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_8005d018();
extern undefined4 FUN_80072564();
extern undefined4 FUN_800d783c();
extern undefined4 FUN_8011e80c();
extern longlong FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern undefined4 DAT_802c28f0;
extern undefined4 DAT_802c28f4;
extern undefined4 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern undefined4 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern undefined4 DAT_803a3be1;
extern undefined4 DAT_803a3be2;
extern uint DAT_803a3c1c;
extern undefined4 DAT_803a3dac;
extern undefined1 gGameplayPreviewSettings;
extern undefined4 DAT_803a3e26;
extern undefined4 DAT_803a3e27;
extern undefined4 DAT_803a3e28;
extern undefined4 DAT_803a3e2a;
extern undefined4 DAT_803a3e2c;
extern undefined4 DAT_803a3e2d;
extern undefined4 gGameplayPreviewColorRed;
extern undefined4 gGameplayPreviewColorGreen;
extern undefined4 gGameplayPreviewColorBlue;
extern undefined4 gGameplayRegisteredDebugOptions;
extern undefined1 DAT_803a3f08;
extern undefined4 DAT_803a3f09;
extern undefined4 DAT_803a3f0c;
extern undefined4 DAT_803a3f0e;
extern undefined4 DAT_803a3f12;
extern undefined4 DAT_803a3f14;
extern undefined4 DAT_803a3f15;
extern undefined4 DAT_803a3f18;
extern undefined4 DAT_803a3f1a;
extern undefined4 DAT_803a3f1e;
extern undefined4 DAT_803a3f21;
extern char DAT_803a3f24;
extern undefined4 DAT_803a3f25;
extern undefined4 DAT_803a3f26;
extern undefined4 DAT_803a3f27;
extern undefined4 DAT_803a3f28;
extern undefined4 DAT_803a3f29;
extern undefined4 DAT_803a3f2b;
extern undefined4 DAT_803a4070;
extern undefined4 DAT_803a4074;
extern undefined4 DAT_803a4078;
extern undefined4 DAT_803a407c;
extern undefined4 DAT_803a4460;
extern undefined4 DAT_803a4465;
extern undefined4 DAT_803a458c;
extern undefined4 DAT_803a4590;
extern undefined4 DAT_803a4594;
extern undefined4 DAT_803a4599;
extern undefined4 DAT_803a459a;
extern undefined4 DAT_803a45aa;
extern undefined4 DAT_803a45ac;
extern undefined4 DAT_803a45b0;
extern undefined4 DAT_803a45b4;
extern undefined4 DAT_803a45b6;
extern undefined4 DAT_803a45ba;
extern undefined4 DAT_803a45bc;
extern undefined4 DAT_803a45be;
extern undefined4 DAT_803a45c0;
extern undefined4 DAT_803a45c2;
extern undefined4 DAT_803a45f0;
extern undefined4 DAT_803a45f1;
extern undefined4 DAT_803a45f2;
extern undefined4 DAT_803a45f3;
extern undefined4 DAT_803a4e78;
extern undefined4 DAT_803dc4f0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e8;
extern undefined4 DAT_803de100;
extern undefined4 DAT_803de104;
extern undefined4 DAT_803de10c;
extern undefined4* DAT_803de110;
extern f32 lbl_803E1348;
extern undefined4 uRam803de108;
extern u8 lbl_803129C8[];
extern f32 lbl_803E0898;
extern f32 lbl_803E089C;
extern f32 lbl_803E08A0;
extern f32 lbl_803E08B8;
extern f32 lbl_803E08A4;
extern f32 lbl_803E08A8;
extern f32 lbl_803E08AC;
extern f32 lbl_803E08B0;
extern f32 lbl_803E08B4;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(uint cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

uint isCheatUnlocked(uint cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
    return;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                      undefined8 param_5, undefined8 param_6, undefined8 param_7,
                      undefined8 param_8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(code**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(code**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((uint)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((uint)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((uint)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

undefined* FUN_800e82d8(void)
{
    return (undefined*)&DAT_803a4460;
}

void FUN_800e8630(int obj)
{
    int placementId;
    undefined1* slot;
    int baseIndex;
    int slotIndex;
    int remaining;

    if ((*(ushort*)&((GameObject*)obj)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    baseIndex = 0;
    slot = &DAT_803a3f08;
    remaining = 9;
    while ((slotIndex = baseIndex, *(int*)(slot + 0x168) != 0 &&
        (placementId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14), placementId != *(int*)(slot + 0x168))))
    {
        slotIndex = baseIndex + 1;
        if ((*(int*)(slot + 0x178) == 0) || (placementId == *(int*)(slot + 0x178))) break;
        slotIndex = baseIndex + 2;
        if ((*(int*)(slot + 0x188) == 0) || (placementId == *(int*)(slot + 0x188))) break;
        slotIndex = baseIndex + 3;
        if ((*(int*)(slot + 0x198) == 0) || (placementId == *(int*)(slot + 0x198))) break;
        slotIndex = baseIndex + 4;
        if ((*(int*)(slot + 0x1a8) == 0) || (placementId == *(int*)(slot + 0x1a8))) break;
        slotIndex = baseIndex + 5;
        if ((*(int*)(slot + 0x1b8) == 0) || (placementId == *(int*)(slot + 0x1b8))) break;
        slotIndex = baseIndex + 6;
        if ((*(int*)(slot + 0x1c8) == 0) || (placementId == *(int*)(slot + 0x1c8))) break;
        slot = slot + 0x70;
        baseIndex = baseIndex + 7;
        remaining = remaining + -1;
        slotIndex = baseIndex;
        if (remaining == 0) break;
    }
    if (slotIndex == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[slotIndex * 4] = *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    (&DAT_803a4074)[slotIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosX;
    (&DAT_803a4078)[slotIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosY;
    (&DAT_803a407c)[slotIndex * 4] = *(undefined4*)&((GameObject*)obj)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 8) = *(undefined4*)&((GameObject*)obj)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)obj)->
        anim.localPosZ;
    return;
}

undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}


undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 savedX;
    undefined4 savedY;
    undefined4 savedZ;
    char* dst;
    int actIndex;
    short* actPtr;
    char* name;
    char cVar8;
    undefined8 uVar9;
    undefined8 uVar10;

    uVar10 = FUN_80286840();
    savedZ = DAT_802c28f8;
    savedY = DAT_802c28f4;
    savedX = DAT_802c28f0;
    name = (char*)((ulonglong)uVar10 >> 0x20);
    FUN_800033a8(-0x7fc5c0f8, 0, 0xf70);
    if ((*(byte*)(DAT_803de110 + 0x21) & 0x80) == 0)
    {
        FUN_800033a8(DAT_803de110, 0, 0x6ec);
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
    actIndex = 0;
    actPtr = &DAT_80312370;
    do
    {
        if (*actPtr != 0)
        {
            (*gMapEventInterface)->setMapAct(actIndex, 1);
        }
        actPtr = actPtr + 1;
        actIndex = actIndex + 1;
    }
    while (actIndex < 0x78);
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = savedX;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = savedY;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = savedZ;
    DAT_803a4465 = 1;
    if (name == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        name = (char*)0x0;
    }
    else
    {
        dst = &DAT_803a3f24;
        do
        {
            cVar8 = *name;
            name = name + 1;
            *dst = cVar8;
            dst = dst + 1;
        }
        while (cVar8 != '\0');
    }
    uVar9 = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    cVar8 = (char)uVar10;
    if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, name != (char*)0x0))
    {
        FUN_80072564(uVar9, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)uVar10 & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int mode)
{
    bool isClearMode;
    char foundIndex;
    uint maskWord;
    char rowBase;
    short* idPtr;
    char* rowPtr;
    uint* flagPtr;
    uint bit;
    uint newMask;
    uint actId;
    char* table;
    int i;
    int j;
    longlong packed;

    packed = FUN_80286830();
    actId = (uint)((ulonglong)packed >> 0x20);
    bit = (uint)packed;
    table = &DAT_803a3be0;
    if (0x4fffffffff < packed)
    {
        actId = (uint)(byte)(&DAT_803a3dac)[actId];
    }
    if ((int)actId < 0x78)
    {
        if ((ushort)(&DAT_80312460)[actId] != 0)
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
            maskWord = FUN_80017690((uint)(ushort)(&DAT_80312460)[actId]);
            if (mode == 0)
            {
                newMask = maskWord & ~(1 << bit);
            }
            else
            {
                newMask = maskWord | 1 << bit;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[actId], newMask);
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
                    i = i + -1;
                }
                while (i != 0);
                if (!isClearMode)
                {
                    rowBase = '\0';
                    i = 4;
                    rowPtr = table;
                    do
                    {
                        if ((((((actId == (int)*rowPtr) && (foundIndex = rowBase, bit == (byte)rowPtr[1])) ||
                                    ((foundIndex = rowBase + '\x01', actId == (int)rowPtr[3] && (bit == (byte)rowPtr[4])))
                                ) || ((foundIndex = rowBase + '\x02', actId == (int)rowPtr[6] &&
                                    (bit == (byte)rowPtr[7])))) ||
                                ((foundIndex = rowBase + '\x03', actId == (int)rowPtr[9] && (bit == (byte)rowPtr[10]))))
                            || ((actId == (int)rowPtr[0xc] &&
                                (foundIndex = rowBase + '\x04', bit == (byte)rowPtr[0xd]))))
                            goto LAB_800e9628;
                        rowPtr = rowPtr + 0xf;
                        rowBase = rowBase + '\x05';
                        i = i + -1;
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
                                (&DAT_803a3be0)[i] = (char)actId;
                                (&DAT_803a3be1)[i] = (char)packed;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            table = table + 3;
                            i = i + 1;
                            j = j + -1;
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
    return;
}

void FUN_800e9e9c(void)
{
    uint index;
    int iVar2;
    undefined4 extraout_r4;
    undefined4 uVar3;
    undefined4 in_r6;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 in_f4;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    DAT_803de10c = 0xff;
    DAT_803de104 = 0xffffffff;
    FUN_80042b9c(0, 0, 1);
    uVar3 = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    index = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[index * 4], (double)(float)(&DAT_803a4590)[index * 4],
                 (double)(float)(&DAT_803a4594)[index * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[index * 0x10], extraout_r4, uVar3, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    iVar2 = FUN_80006b7c();
    if (iVar2 != 4)
    {
        FUN_80006b84(1);
    }
    FUN_800d783c(0x1e, 1);
    DAT_803de100 = 2;
    return;
}

undefined4
FUN_800ea8c8(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 result;
    undefined* hist;

    result = FUN_80017498();
    hist = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)hist[5] * 2)
    ]
    )
    ;
    return result;
}

undefined FUN_800ea9ac(void)
{
    undefined* hist;

    hist = FUN_800e82d8();
    return hist[5];
}

void FUN_800ea9b8(void)
{
    uint id;
    undefined* hist;
    short i;
    uint mask;
    uint bit;
    uint wordId;
    uint cachedMask;
    uint lastWordId;
    uint scanId;
    short* idPtr;

    id = FUN_80286834();
    hist = FUN_800e82d8();
    lastWordId = 0xffffffff;
    if (hist[6] == '\0')
    {
        idPtr = &DAT_80312632;
        for (scanId = 1; (short)scanId < 0xce; scanId = scanId + 1)
        {
            if ((*idPtr == 0xffff) || (*idPtr == -1))
            {
                bit = 1 << (scanId & 0x1f);
                wordId = (uint)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
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
    mask = (uint)(short)((short)((id & 0xff) >> 5) + 0x12f);
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
        *hist = (char)id;
        if ((uint)(byte)hist[5] == (id & 0xff)
        )
        {
            do
            {
                hist[5] = hist[5] + '\x01';
                id = (uint)(short)(((byte)hist[5] >> 5) + 0x12f);
                if (id != (int)(short)lastWordId)
                {
                    cachedMask = FUN_80017690(id);
                    lastWordId = id;
                }
            }
            while ((cachedMask & 1 << ((byte)hist[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void dll_62_func01_nop(void)
{
}

void dll_62_func00_nop(void)
{
}

void dll_63_func01_nop(void);

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* lbl = N (byte) */

/* 12b 3-insn patterns. */

/* misc 8b leaves */

/* if (lbl) fn(lbl); */

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void dll_62_func03(int sourceObj, int variant, int posSource, uint flags)
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
    GfxCmd* e = buf.entries;
    u8* base = lbl_803129C8;
    int ctx;
    u8 cnt;
    f32 v;
    v = lbl_803E0898;
    cnt = *(u8*)(*(int*)(sourceObj + 76) + 26);
    if (variant == 1)
    {
        *(s16*)&base[478] = 0;
        v = lbl_803E089C;
    }
    else if (variant == 2)
    {
        v = lbl_803E08A0;
        cnt = 6;
    }
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E08A0;
    e[0].y = lbl_803E08A0;
    e[0].z = lbl_803E08A0;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &base[404];
    e[1].mode = 2;
    e[1].x = lbl_803E08A4;
    e[1].y = lbl_803E08A8;
    e[1].z = lbl_803E08A4;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &base[372];
    e[2].mode = 2;
    e[2].x = lbl_803E08A4;
    e[2].y = lbl_803E08A8;
    e[2].z = lbl_803E08A4;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[372];
    e[3].mode = 4;
    e[3].x = lbl_803E08AC;
    e[3].y = lbl_803E08A0;
    e[3].z = lbl_803E08A0;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[388];
    e[4].mode = 4;
    e[4].x = lbl_803E08AC;
    e[4].y = lbl_803E08A0;
    e[4].z = lbl_803E08A0;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x100;
    e[5].x = lbl_803E08A0;
    e[5].y = lbl_803E08A0;
    e[5].z = lbl_803E08B0;
    e[6].layer = 2;
    e[6].flags = 0x3a;
    e[6].tex = (void*)0;
    e[6].mode = 0x1800000;
    e[6].x = v;
    e[6].y = lbl_803E08A0;
    e[6].z = lbl_803E08B4;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x100;
    e[7].x = lbl_803E08A0;
    e[7].y = lbl_803E08A0;
    e[7].z = lbl_803E08B0;
    e[8].layer = 3;
    e[8].flags = 0x3a;
    e[8].tex = (void*)0;
    e[8].mode = 0x1800000;
    e[8].x = v;
    e[8].y = lbl_803E08A0;
    e[8].z = lbl_803E08B4;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = &base[432];
    e[9].mode = 0x100;
    e[9].x = lbl_803E08A0;
    e[9].y = lbl_803E08A0;
    e[9].z = lbl_803E08B0;
    e[10].layer = 4;
    e[10].flags = 2;
    e[10].tex = (void*)0;
    e[10].mode = 0x2000;
    e[10].x = lbl_803E08A0;
    e[10].y = lbl_803E08A0;
    e[10].z = lbl_803E08A0;
    e[11].layer = 5;
    e[11].flags = 7;
    e[11].tex = &base[372];
    e[11].mode = 4;
    e[11].x = lbl_803E08A0;
    e[11].y = lbl_803E08A0;
    e[11].z = lbl_803E08A0;
    e[12].layer = 5;
    e[12].flags = 7;
    e[12].tex = &base[388];
    e[12].mode = 4;
    e[12].x = lbl_803E08A0;
    e[12].y = lbl_803E08A0;
    e[12].z = lbl_803E08A0;
    e[13].layer = 5;
    e[13].flags = 0x15;
    e[13].tex = &base[432];
    e[13].mode = 0x100;
    e[13].x = lbl_803E08A0;
    e[13].y = lbl_803E08A0;
    e[13].z = lbl_803E08B0;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0898;
    buf.pos[1] = lbl_803E0898;
    buf.pos[2] = lbl_803E0898;
    buf.col[0] = lbl_803E08A0;
    buf.col[1] = lbl_803E08A0;
    buf.col[2] = lbl_803E08A0;
    if (cnt != 0)
    {
        buf.scale = lbl_803E08B8 * (f32)(u32)cnt;
    }
    else
    {
        buf.scale = lbl_803E0898;
    }
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 14;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = buf.entries;
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0898 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0898 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0898 + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0898 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0898 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0898 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, &base[0], 0x18, &base[212], 0x5e0, 0);
}

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

