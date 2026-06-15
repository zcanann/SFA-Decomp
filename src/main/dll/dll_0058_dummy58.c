#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"

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
    int key;
    undefined1* entry;
    int base;
    int slot;
    int remaining;

    if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    base = 0;
    entry = &DAT_803a3f08;
    remaining = 9;
    while ((slot = base, *(int*)(entry + 0x168) != 0 &&
        (key = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14), key != *(int*)(entry + 0x168))))
    {
        slot = base + 1;
        if ((*(int*)(entry + 0x178) == 0) || (key == *(int*)(entry + 0x178))) break;
        slot = base + 2;
        if ((*(int*)(entry + 0x188) == 0) || (key == *(int*)(entry + 0x188))) break;
        slot = base + 3;
        if ((*(int*)(entry + 0x198) == 0) || (key == *(int*)(entry + 0x198))) break;
        slot = base + 4;
        if ((*(int*)(entry + 0x1a8) == 0) || (key == *(int*)(entry + 0x1a8))) break;
        slot = base + 5;
        if ((*(int*)(entry + 0x1b8) == 0) || (key == *(int*)(entry + 0x1b8))) break;
        slot = base + 6;
        if ((*(int*)(entry + 0x1c8) == 0) || (key == *(int*)(entry + 0x1c8))) break;
        entry = entry + 0x70;
        base = base + 7;
        remaining = remaining + -1;
        slot = base;
        if (remaining == 0) break;
    }
    if (slot == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[slot * 4] = *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[slot * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[slot * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[slot * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosZ;
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


undefined FUN_800e8b98(void)
{
    return DAT_803de100;
}

void FUN_800e8f58(undefined8 param_1, double param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined4 uVar1;
    undefined4 uVar2;
    undefined4 uVar3;
    char* pcVar4;
    int iVar5;
    short* psVar6;
    char* pcVar7;
    char cVar8;
    undefined8 uVar9;
    undefined8 uVar10;

    uVar10 = FUN_80286840();
    uVar3 = DAT_802c28f8;
    uVar2 = DAT_802c28f4;
    uVar1 = DAT_802c28f0;
    pcVar7 = (char*)((ulonglong)uVar10 >> 0x20);
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
    iVar5 = 0;
    psVar6 = &DAT_80312370;
    do
    {
        if (*psVar6 != 0)
        {
            (*gMapEventInterface)->setMapAct(iVar5, 1);
        }
        psVar6 = psVar6 + 1;
        iVar5 = iVar5 + 1;
    }
    while (iVar5 < 0x78);
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
    (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = uVar1;
    (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = uVar2;
    (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = uVar3;
    DAT_803a4465 = 1;
    if (pcVar7 == (char*)0x0)
    {
        DAT_803a3f24 = 0x46;
        DAT_803a3f25 = 0x4f;
        DAT_803a3f26 = 0x58;
        DAT_803a3f27 = 0;
        pcVar7 = (char*)0x0;
    }
    else
    {
        pcVar4 = &DAT_803a3f24;
        do
        {
            cVar8 = *pcVar7;
            pcVar7 = pcVar7 + 1;
            *pcVar4 = cVar8;
            pcVar4 = pcVar4 + 1;
        }
        while (cVar8 != '\0');
    }
    uVar9 = FUN_80003494(DAT_803de110, 0x803a3f08, 0x6ec);
    cVar8 = (char)uVar10;
    if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, pcVar7 != (char*)0x0))
    {
        FUN_80072564(uVar9, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (uint)uVar10 & 0xff,
                     DAT_803de110, &gGameplayPreviewSettings);
    }
    FUN_8028688c();
    return;
}

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int mode)
{
    bool bVar1;
    char cVar2;
    uint flags;
    char cVar4;
    short* evtWalk;
    char* pcVar6;
    uint* flagWalk;
    uint bit;
    uint newFlags;
    uint eventId;
    char* pcVar11;
    int cnt;
    int iVar13;
    longlong lVar14;

    lVar14 = FUN_80286830();
    eventId = (uint)((ulonglong)lVar14 >> 0x20);
    bit = (uint)lVar14;
    pcVar11 = &DAT_803a3be0;
    if (0x4fffffffff < lVar14)
    {
        eventId = (uint)(byte)(&DAT_803a3dac)[eventId];
    }
    if ((int)eventId < 0x78)
    {
        if ((ushort)(&DAT_80312460)[eventId] != 0)
        {
            if (mode == -1)
            {
                mode = 1;
            }
            bVar1 = mode == -2;
            if (bVar1)
            {
                mode = 0;
            }
            flags = FUN_80017690((uint)(ushort)(&DAT_80312460)[eventId]);
            if (mode == 0)
            {
                newFlags = flags & ~(1 << bit);
            }
            else
            {
                newFlags = flags | 1 << bit;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[eventId], newFlags);
            DAT_803de104 = eventId;
            uRam803de108 = newFlags;
            if (mode == 0)
            {
                evtWalk = &DAT_80312460;
                flagWalk = &DAT_803a3c1c;
                flags = ~(1 << bit);
                cnt = 0x14;
                do
                {
                    if (*evtWalk == (&DAT_80312460)[eventId])
                    {
                        *flagWalk = *flagWalk & flags;
                    }
                    if (evtWalk[1] == (&DAT_80312460)[eventId])
                    {
                        flagWalk[1] = flagWalk[1] & flags;
                    }
                    if (evtWalk[2] == (&DAT_80312460)[eventId])
                    {
                        flagWalk[2] = flagWalk[2] & flags;
                    }
                    if (evtWalk[3] == (&DAT_80312460)[eventId])
                    {
                        flagWalk[3] = flagWalk[3] & flags;
                    }
                    if (evtWalk[4] == (&DAT_80312460)[eventId])
                    {
                        flagWalk[4] = flagWalk[4] & flags;
                    }
                    if (evtWalk[5] == (&DAT_80312460)[eventId])
                    {
                        flagWalk[5] = flagWalk[5] & flags;
                    }
                    evtWalk = evtWalk + 6;
                    flagWalk = flagWalk + 6;
                    cnt = cnt + -1;
                }
                while (cnt != 0);
                if (!bVar1)
                {
                    cVar4 = '\0';
                    cnt = 4;
                    pcVar6 = pcVar11;
                    do
                    {
                        if ((((((eventId == (int)*pcVar6) && (cVar2 = cVar4, bit == (byte)pcVar6[1])) ||
                                    ((cVar2 = cVar4 + '\x01', eventId == (int)pcVar6[3] && (bit == (byte)pcVar6[4])))
                                ) || ((cVar2 = cVar4 + '\x02', eventId == (int)pcVar6[6] &&
                                    (bit == (byte)pcVar6[7])))) ||
                                ((cVar2 = cVar4 + '\x03', eventId == (int)pcVar6[9] && (bit == (byte)pcVar6[10]))))
                            || ((eventId == (int)pcVar6[0xc] &&
                                (cVar2 = cVar4 + '\x04', bit == (byte)pcVar6[0xd]))))
                            goto LAB_800e9628;
                        pcVar6 = pcVar6 + 0xf;
                        cVar4 = cVar4 + '\x05';
                        cnt = cnt + -1;
                    }
                    while (cnt != 0);
                    cVar2 = -1;
                LAB_800e9628:
                    if (cVar2 == -1)
                    {
                        cnt = 0;
                        iVar13 = 0x14;
                        do
                        {
                            if (*pcVar11 == -1)
                            {
                                cnt = cnt * 3;
                                (&DAT_803a3be0)[cnt] = (char)eventId;
                                (&DAT_803a3be1)[cnt] = (char)lVar14;
                                (&DAT_803a3be2)[cnt] = 3;
                                break;
                            }
                            pcVar11 = pcVar11 + 3;
                            cnt = cnt + 1;
                            iVar13 = iVar13 + -1;
                        }
                        while (iVar13 != 0);
                    }
                }
            }
            else
            {
                bit = 1 << bit;
                if ((flags & bit) == 0)
                {
                    evtWalk = &DAT_80312460;
                    flagWalk = &DAT_803a3c1c;
                    cnt = 0x14;
                    do
                    {
                        if (*evtWalk == (&DAT_80312460)[eventId])
                        {
                            *flagWalk = *flagWalk | bit;
                        }
                        if (evtWalk[1] == (&DAT_80312460)[eventId])
                        {
                            flagWalk[1] = flagWalk[1] | bit;
                        }
                        if (evtWalk[2] == (&DAT_80312460)[eventId])
                        {
                            flagWalk[2] = flagWalk[2] | bit;
                        }
                        if (evtWalk[3] == (&DAT_80312460)[eventId])
                        {
                            flagWalk[3] = flagWalk[3] | bit;
                        }
                        if (evtWalk[4] == (&DAT_80312460)[eventId])
                        {
                            flagWalk[4] = flagWalk[4] | bit;
                        }
                        if (evtWalk[5] == (&DAT_80312460)[eventId])
                        {
                            flagWalk[5] = flagWalk[5] | bit;
                        }
                        evtWalk = evtWalk + 6;
                        flagWalk = flagWalk + 6;
                        cnt = cnt + -1;
                    }
                    while (cnt != 0);
                }
            }
        }
    }
    FUN_8028687c();
    return;
}

void FUN_800e9e9c(void)
{
    uint uVar1;
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
    uVar1 = (uint)DAT_803a3f28;
    FUN_800176dc((double)(float)(&DAT_803a458c)[uVar1 * 4], (double)(float)(&DAT_803a4590)[uVar1 * 4],
                 (double)(float)(&DAT_803a4594)[uVar1 * 4], in_f4, in_f5, in_f6, in_f7, in_f8,
                 (int)(char)(&DAT_803a4599)[uVar1 * 0x10], extraout_r4, uVar3, in_r6, in_r7, in_r8, in_r9,
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
    undefined4 uVar1;
    undefined* puVar2;

    uVar1 = FUN_80017498();
    puVar2 = FUN_800e82d8();
    FUN_80017488(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                 (uint)(byte)(&DAT_803a4e78)[*(short*)(&DAT_80312630 + (uint)(byte)puVar2[5] * 2)
    ]
    )
    ;
    return uVar1;
}

undefined FUN_800ea9ac(void)
{
    undefined* puVar1;

    puVar1 = FUN_800e82d8();
    return puVar1[5];
}

void FUN_800ea9b8(void)
{
    uint uVar1;
    undefined* hist;
    short sVar3;
    uint flags;
    uint uVar5;
    uint bit;
    uint unaff_r27;
    uint uVar7;
    uint uVar8;
    short* psVar9;

    uVar1 = FUN_80286834();
    hist = FUN_800e82d8();
    uVar7 = 0xffffffff;
    if (hist[6] == '\0')
    {
        psVar9 = &DAT_80312632;
        for (uVar8 = 1; (short)uVar8 < 0xce; uVar8 = uVar8 + 1)
        {
            if ((*psVar9 == 0xffff) || (*psVar9 == -1))
            {
                uVar5 = 1 << (uVar8 & 0x1f);
                bit = (uint)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
                flags = FUN_80017690(bit);
                if ((flags & uVar5) == 0)
                {
                    FUN_80017698(bit, flags | uVar5);
                }
            }
            psVar9 = psVar9 + 1;
        }
    }
    bit = 1 << (uVar1 & 0x1f);
    flags = (uint)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
    uVar8 = FUN_80017690(flags);
    if ((uVar8 & bit) == 0)
    {
        FUN_80017698(flags, uVar8 | bit);
        if (hist[6] != '\x05')
        {
            hist[6] = hist[6] + '\x01';
        }
        for (sVar3 = 4; sVar3 != 0; sVar3 = sVar3 + -1)
        {
            hist[sVar3] = hist[sVar3 + -1];
        }
        *hist = (char)uVar1;
        if ((uint)(byte)hist[5] == (uVar1 & 0xff)
        )
        {
            do
            {
                hist[5] = hist[5] + '\x01';
                uVar1 = (uint)(short)(((byte)hist[5] >> 5) + 0x12f);
                if (uVar1 != (int)(short)uVar7)
                {
                    unaff_r27 = FUN_80017690(uVar1);
                    uVar7 = uVar1;
                }
            }
            while ((unaff_r27 & 1 << ((byte)hist[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void Dummy58_release(void)
{
}

void Dummy58_initialise(void)
{
}

void dll_69_func01_nop(void);

int Dummy58_func03_ret_0(void) { return 0x0; }
int Dummy6C_func03_ret_0(void);

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

