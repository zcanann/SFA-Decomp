#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/dll/player_objects.h"
#include "main/mapEventTypes.h"

typedef struct CarryableUpdateHeldState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    u8 pad4[0x5 - 0x4];
    s8 unk5;
    u8 unk6;
    u8 unk7;
    u8 unk8;
    u8 pad9[0x10 - 0x9];
} CarryableUpdateHeldState;

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
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
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
extern void* Obj_GetPlayerObject(void);
extern void playerSetHeldObject(void* player, int held);
extern f32 lbl_803E06D8;
extern uint buttonGetDisabled(int idx);
extern void buttonDisable(int index, uint flags);
extern uint getButtonsJustPressed(int idx);
extern int fn_80295BF0(void* player);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int hitDetectFn_80065e50(u8* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 timeDelta;
extern const f32 lbl_803E06DC, lbl_803E06E0, lbl_803E06E4, lbl_803E06E8;

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

void FUN_800e8630(int param_1)
{
    int placementId;
    undefined1* slot;
    int baseIndex;
    int foundIndex;
    int remaining;

    if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
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
    while ((foundIndex = baseIndex, *(int*)(slot + 0x168) != 0 &&
        (placementId = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14), placementId != *(int*)(slot + 0x168))))
    {
        foundIndex = baseIndex + 1;
        if ((*(int*)(slot + 0x178) == 0) || (placementId == *(int*)(slot + 0x178))) break;
        foundIndex = baseIndex + 2;
        if ((*(int*)(slot + 0x188) == 0) || (placementId == *(int*)(slot + 0x188))) break;
        foundIndex = baseIndex + 3;
        if ((*(int*)(slot + 0x198) == 0) || (placementId == *(int*)(slot + 0x198))) break;
        foundIndex = baseIndex + 4;
        if ((*(int*)(slot + 0x1a8) == 0) || (placementId == *(int*)(slot + 0x1a8))) break;
        foundIndex = baseIndex + 5;
        if ((*(int*)(slot + 0x1b8) == 0) || (placementId == *(int*)(slot + 0x1b8))) break;
        foundIndex = baseIndex + 6;
        if ((*(int*)(slot + 0x1c8) == 0) || (placementId == *(int*)(slot + 0x1c8))) break;
        slot = slot + 0x70;
        baseIndex = baseIndex + 7;
        remaining = remaining + -1;
        foundIndex = baseIndex;
        if (remaining == 0) break;
    }
    if (foundIndex == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[foundIndex * 4] = *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[foundIndex * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosZ;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 8) = *(undefined4*)&((GameObject*)param_1)->anim
        .localPosX;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0xc) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosY;
    *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x10) = *(undefined4*)&((GameObject*)param_1)->
        anim.localPosZ;
    return;
}

undefined4* FUN_800e87a8(void)
{
    return &DAT_803a45b0;
}

int saveFn_800e8508(void);

undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 colorX;
    undefined4 colorY;
    undefined4 colorZ;
    char* dst;
    int mapAct;
    short* mapActPtr;
    char* name;
    char cVar8;
    undefined8 uVar9;
    undefined8 uVar10;

    uVar10 = FUN_80286840();
    colorZ = DAT_802c28f8;
    colorY = DAT_802c28f4;
    colorX = DAT_802c28f0;
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
    mapAct = 0;
    mapActPtr = &DAT_80312370;
    do
    {
        if (*mapActPtr != 0)
        {
            (*gMapEventInterface)->setMapAct(mapAct, 1);
        }
        mapActPtr = mapActPtr + 1;
        mapAct = mapAct + 1;
    }
    while (mapAct < 0x78);
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = colorX;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = colorY;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = colorZ;
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

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool clearMode;
    char foundSlot;
    uint flags;
    char slotBase;
    short* groupPtr;
    char* histEntry;
    uint* cachePtr;
    uint bitNo;
    uint newFlags;
    uint group;
    char* hist;
    int i;
    int j;
    longlong packed;

    packed = FUN_80286830();
    group = (uint)((ulonglong)packed >> 0x20);
    bitNo = (uint)packed;
    hist = &DAT_803a3be0;
    if (0x4fffffffff < packed)
    {
        group = (uint)(byte)(&DAT_803a3dac)[group];
    }
    if ((int)group < 0x78)
    {
        if ((ushort)(&DAT_80312460)[group] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            clearMode = param_3 == -2;
            if (clearMode)
            {
                param_3 = 0;
            }
            flags = FUN_80017690((uint)(ushort)(&DAT_80312460)[group]);
            if (param_3 == 0)
            {
                newFlags = flags & ~(1 << bitNo);
            }
            else
            {
                newFlags = flags | 1 << bitNo;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[group], newFlags);
            DAT_803de104 = group;
            uRam803de108 = newFlags;
            if (param_3 == 0)
            {
                groupPtr = &DAT_80312460;
                cachePtr = &DAT_803a3c1c;
                flags = ~(1 << bitNo);
                i = 0x14;
                do
                {
                    if (*groupPtr == (&DAT_80312460)[group])
                    {
                        *cachePtr = *cachePtr & flags;
                    }
                    if (groupPtr[1] == (&DAT_80312460)[group])
                    {
                        cachePtr[1] = cachePtr[1] & flags;
                    }
                    if (groupPtr[2] == (&DAT_80312460)[group])
                    {
                        cachePtr[2] = cachePtr[2] & flags;
                    }
                    if (groupPtr[3] == (&DAT_80312460)[group])
                    {
                        cachePtr[3] = cachePtr[3] & flags;
                    }
                    if (groupPtr[4] == (&DAT_80312460)[group])
                    {
                        cachePtr[4] = cachePtr[4] & flags;
                    }
                    if (groupPtr[5] == (&DAT_80312460)[group])
                    {
                        cachePtr[5] = cachePtr[5] & flags;
                    }
                    groupPtr = groupPtr + 6;
                    cachePtr = cachePtr + 6;
                    i = i + -1;
                }
                while (i != 0);
                if (!clearMode)
                {
                    slotBase = '\0';
                    i = 4;
                    histEntry = hist;
                    do
                    {
                        if ((((((group == (int)*histEntry) && (foundSlot = slotBase, bitNo == (byte)histEntry[1])) ||
                                    ((foundSlot = slotBase + '\x01', group == (int)histEntry[3] && (bitNo == (byte)histEntry[4])))
                                ) || ((foundSlot = slotBase + '\x02', group == (int)histEntry[6] &&
                                    (bitNo == (byte)histEntry[7])))) ||
                                ((foundSlot = slotBase + '\x03', group == (int)histEntry[9] && (bitNo == (byte)histEntry[10]))))
                            || ((group == (int)histEntry[0xc] &&
                                (foundSlot = slotBase + '\x04', bitNo == (byte)histEntry[0xd]))))
                            goto LAB_800e9628;
                        histEntry = histEntry + 0xf;
                        slotBase = slotBase + '\x05';
                        i = i + -1;
                    }
                    while (i != 0);
                    foundSlot = -1;
                LAB_800e9628:
                    if (foundSlot == -1)
                    {
                        i = 0;
                        j = 0x14;
                        do
                        {
                            if (*hist == -1)
                            {
                                i = i * 3;
                                (&DAT_803a3be0)[i] = (char)group;
                                (&DAT_803a3be1)[i] = (char)packed;
                                (&DAT_803a3be2)[i] = 3;
                                break;
                            }
                            hist = hist + 3;
                            i = i + 1;
                            j = j + -1;
                        }
                        while (j != 0);
                    }
                }
            }
            else
            {
                bitNo = 1 << bitNo;
                if ((flags & bitNo) == 0)
                {
                    groupPtr = &DAT_80312460;
                    cachePtr = &DAT_803a3c1c;
                    i = 0x14;
                    do
                    {
                        if (*groupPtr == (&DAT_80312460)[group])
                        {
                            *cachePtr = *cachePtr | bitNo;
                        }
                        if (groupPtr[1] == (&DAT_80312460)[group])
                        {
                            cachePtr[1] = cachePtr[1] | bitNo;
                        }
                        if (groupPtr[2] == (&DAT_80312460)[group])
                        {
                            cachePtr[2] = cachePtr[2] | bitNo;
                        }
                        if (groupPtr[3] == (&DAT_80312460)[group])
                        {
                            cachePtr[3] = cachePtr[3] | bitNo;
                        }
                        if (groupPtr[4] == (&DAT_80312460)[group])
                        {
                            cachePtr[4] = cachePtr[4] | bitNo;
                        }
                        if (groupPtr[5] == (&DAT_80312460)[group])
                        {
                            cachePtr[5] = cachePtr[5] | bitNo;
                        }
                        groupPtr = groupPtr + 6;
                        cachePtr = cachePtr + 6;
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
    uint slotIndex;
    int mode;
    undefined4 extraout_r4;
    undefined4 size;
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
    size = 0x884;
    FUN_800033a8(-0x7fc5ba0c, 0, 0x884);
    FUN_800176cc();
    FUN_80006770(7);
    FUN_80006b8c();
    FUN_8011e80c();
    slotIndex = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[slotIndex * 4], (double)(float)(&DAT_803a4590)[slotIndex * 4],
                 (double)(float)(&DAT_803a4594)[slotIndex * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[slotIndex * 0x10], extraout_r4, size, in_r6, in_r7, in_r8, in_r9,
                 in_r10);
    mode = FUN_80006b7c();
    if (mode != 4)
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
    undefined* state;

    result = FUN_80017498();
    state = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)state[5] * 2)
    ]
    )
    ;
    return result;
}

undefined FUN_800ea9ac(void)
{
    undefined* state;

    state = FUN_800e82d8();
    return state[5];
}

void FUN_800ea9b8(void)
{
    uint id;
    undefined* state;
    short i;
    uint flags;
    uint mask;
    uint bit;
    uint cachedFlags;
    uint lastBitWord;
    uint scanId;
    short* entry;

    id = FUN_80286834();
    state = FUN_800e82d8();
    lastBitWord = 0xffffffff;
    if (state[6] == '\0')
    {
        entry = &DAT_80312632;
        for (scanId = 1; (short)scanId < 0xce; scanId = scanId + 1)
        {
            if ((*entry == 0xffff) || (*entry == -1))
            {
                mask = 1 << (scanId & 0x1f);
                bit = (uint)(short)((short)((scanId & 0xff) >> 5) + 0x12f);
                flags = FUN_80017690(bit);
                if ((flags & mask) == 0)
                {
                    FUN_80017698(bit, flags | mask);
                }
            }
            entry = entry + 1;
        }
    }
    bit = 1 << (id & 0x1f);
    flags = (uint)(short)((short)((id & 0xff) >> 5) + 0x12f);
    scanId = FUN_80017690(flags);
    if ((scanId & bit) == 0)
    {
        FUN_80017698(flags, scanId | bit);
        if (state[6] != '\x05')
        {
            state[6] = state[6] + '\x01';
        }
        for (i = 4; i != 0; i = i + -1)
        {
            state[i] = state[i + -1];
        }
        *state = (char)id;
        if ((uint)(byte)state[5] == (id & 0xff)
        )
        {
            do
            {
                state[5] = state[5] + '\x01';
                id = (uint)(short)(((byte)state[5] >> 5) + 0x12f);
                if (id != (int)(short)lastBitWord)
                {
                    cachedFlags = FUN_80017690(id);
                    lastBitWord = id;
                }
            }
            while ((cachedFlags & 1 << ((byte)state[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void Carryable_release(void)
{
}

void Carryable_initialise(void)
{
}

void dll_59_func01_nop(void);

void Carryable_init(int obj, int state)
{
    ObjGroup_AddObject(obj, 0x10);
    *(undefined2*)(state + 2) = 0;
    *(undefined*)(state + 5) = 0;
    *(undefined*)(state + 4) = 0;
    *(undefined*)(state + 6) = 0;
    *(undefined4*)(obj + 0xf8) = 0;
}

void Carryable_free(int x) { ObjGroup_RemoveObject(x, 0x10); }

void clearSaveGameLoadingFlag(void);

s32 Carryable_isHeld(u8* obj) { return *(s8*)(obj + 0x5); }
s32 Carryable_getFlag01(u8* state) { return state[7] & 1; }

void Carryable_setFlag08(u8* state, u8 enable)
{
    if (enable != 0)
    {
        state[7] |= 8;
    }
    else
    {
        state[7] &= ~8;
    }
}

s32 Carryable_getFlag04(u8* state) { return (state[7] & 4) != 0; }

void Carryable_setFlag04(u8* state, u8 enable)
{
    if (enable != 0)
    {
        state[7] |= 4;
    }
    else
    {
        state[7] &= ~4;
    }
}

void Carryable_setFlag02Inverted(u8* state, u8 clear)
{
    if (clear != 0)
    {
        state[7] &= ~2;
    }
    else
    {
        state[7] |= 2;
    }
}

u8 Carryable_getSurfaceType(u8* state) { return state[8]; }

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void saveGame_saveObjectPos(int* obj);

int Carryable_updateHeld(u8* obj)
{
    f32** list;
    u8* held;
    void* player;
    held = ((GameObject*)obj)->extra;
    ((CarryableUpdateHeldState*)held)->unk8 = 0;
    ((CarryableUpdateHeldState*)held)->unk7 &= ~1;
    player = Obj_GetPlayerObject();
    if (((CarryableUpdateHeldState*)held)->unk5 == 0)
    {
        struct
        {
            u8 a, b, c, d, e;
        } * t;
        int v = 0;
        t = (void*)(*(u8**)(obj + 0x78) + ((GameObject*)obj)->unkE4 * 5);
        if ((t->e & 0xf) == 6
            && (buttonGetDisabled(0) & 0x100) == 0
            && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0
            && ((GameObject*)obj)->unkF8 == 0)
        {
            *(s16*)held = 0;
            buttonDisable(0, 0x100);
            v = 1;
        }
        ((CarryableUpdateHeldState*)held)->unk5 = v;
        if (((CarryableUpdateHeldState*)held)->unk5 != 0)
        {
            ((CarryableUpdateHeldState*)held)->unk7 |= 1;
            ((CarryableUpdateHeldState*)held)->unk6 = 1;
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            int cnt, i, j;
            f32** p;
            u8* hit;
            ObjHits_SyncObjectPositionIfDirty(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            if ((((CarryableUpdateHeldState*)held)->unk7 & 2) == 0)
            {
                ((GameObject*)obj)->anim.velocityY = -(lbl_803E06DC * timeDelta - ((GameObject*)obj)->anim.velocityY);
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)
                    ->anim.localPosY;
            }
            cnt = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                       ((GameObject*)obj)->anim.localPosZ, &list, 0, 1);
            hit = (u8*)0;
            i = 0;
            p = list;
            for (j = cnt; j > 0; j--)
            {
                if (*(s8*)((u8*)*p + 0x14) != 0xe)
                {
                    if (((GameObject*)obj)->anim.localPosY < **p && ((GameObject*)obj)->anim.localPosY > **p -
                        lbl_803E06E0)
                    {
                        hit = *(u8**)(list[i] + 4);
                        ((GameObject*)obj)->anim.localPosY = *list[i];
                        ((GameObject*)obj)->anim.velocityY = lbl_803E06E4;
                        break;
                    }
                }
                p++;
                i++;
            }
            i = 0;
            for (; cnt > 0; cnt--)
            {
                f32 d = ((GameObject*)obj)->anim.localPosY - *list[i];
                if (d < lbl_803E06E4)
                {
                    d = -d;
                }
                if (d < lbl_803E06E8)
                {
                    s8 t2 = *(s8*)((u8*)list[i] + 0x14);
                    if (t2 > ((CarryableUpdateHeldState*)held)->unk8)
                    {
                        *(s8*)&((CarryableUpdateHeldState*)held)->unk8 = t2;
                    }
                }
                i++;
            }
            if (hit != 0)
            {
                u8* q = *(u8**)(hit + 0x58);
                u8* q2;
                u8 c = *(u8*)(q + 0x10f);
                *(u8*)(q + 0x10f) = c + 1;
                q2 = q + (s8)c * 4;
                *(u8**)(q2 + 0x100) = obj;
            }
        }
    }
    else
    {
        ObjHits_MarkObjectPositionDirty(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if ((getButtonsJustPressed(0) & 0x100) != 0)
        {
            if ((((CarryableUpdateHeldState*)held)->unk7 & 4) != 0 || fn_80295BF0(player) == 0)
            {
                Sfx_PlayFromObject(0, 0x10a);
            }
            else
            {
                buttonDisable(0, 0x100);
                ((CarryableUpdateHeldState*)held)->unk6 = 0;
            }
        }
        if (((GameObject*)obj)->unkF8 == 1)
        {
            ((CarryableUpdateHeldState*)held)->unk5 = 2;
        }
        if (((CarryableUpdateHeldState*)held)->unk5 == 2 && ((GameObject*)obj)->unkF8 == 0)
        {
            u8* h2 = ((GameObject*)obj)->extra;
            *(u8*)&((CarryableUpdateHeldState*)h2)->unk5 = 0;
            ((CarryableUpdateHeldState*)h2)->unk6 = 0;
            if ((((CarryableUpdateHeldState*)h2)->unk7 & 8) == 0)
            {
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E06D8;
                saveGame_saveObjectPos((int*)obj);
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E06D8;
            }
        }
        if (*(s8*)&((CarryableUpdateHeldState*)held)->unk6 != 0)
        {
            ObjMsg_SendToObject(player, 0x100008, obj,
                                (((CarryableUpdateHeldState*)held)->unk2 << 16) | (u16) * (s16*)held);
        }
    }
    return ((CarryableUpdateHeldState*)held)->unk5;
}

void objSaveFn_800ea774(int* obj)
{
    u8* sub = ((GameObject*)obj)->extra;
    sub[5] = 0;
    sub[6] = 0;
    if ((sub[7] & 8) == 0)
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E06D8;
        saveGame_saveObjectPos(obj);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E06D8;
    }
}

void saveGame_saveObjectPos(int* obj);

void Carryable_stopCarrying(int* obj, u8* param2)
{
    void* player = Obj_GetPlayerObject();
    int held;
    param2[5] = 0;
    Player_GetHeldObject((int)player, &held);
    if ((int*)held == obj)
    {
        playerSetHeldObject(player, 0);
    }
}

int Carryable_updateRenderState(int* obj, int flag)
{
    int* p50 = *(int**)&((GameObject*)obj)->anim.modelInstance;
    if (((ObjDef*)p50)->shadowType == 2)
    {
        if (((GameObject*)obj)->seqIndex == -1)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        else
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (((GameObject*)obj)->unkF8 != 0)
    {
        if (flag != -1) return 0;
    }
    else
    {
        if (flag == 0) return 0;
    }
    return 1;
}

void SaveGame_setCamActionNo(s16 actionNo);

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, uint flags);
