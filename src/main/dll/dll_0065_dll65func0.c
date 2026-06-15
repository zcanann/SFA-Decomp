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
extern int maybeTryLoadSave(int a);
extern u8 lbl_80312E58[];
extern f32 lbl_803E0930;
extern f32 lbl_803E0934;
extern f32 lbl_803E0938;
extern f32 lbl_803E093C;
extern f32 lbl_803E0940;
extern f32 lbl_803E0944;
extern f32 lbl_803E0948;
extern f32 lbl_803E094C;
extern f32 lbl_803E0950;
extern f32 lbl_803E0954;
extern f32 lbl_803E0958;
extern f32 lbl_803E095C;
extern f32 lbl_803E0960;

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
    int iVar1;
    undefined1* puVar2;
    int iVar3;
    int iVar4;
    int iVar5;

    if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) != 0)
    {
        return;
    }
    if (DAT_803de100 != '\0')
    {
        return;
    }
    iVar3 = 0;
    puVar2 = &DAT_803a3f08;
    iVar5 = 9;
    while ((iVar4 = iVar3, *(int*)(puVar2 + 0x168) != 0 &&
        (iVar1 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14), iVar1 != *(int*)(puVar2 + 0x168))))
    {
        iVar4 = iVar3 + 1;
        if ((*(int*)(puVar2 + 0x178) == 0) || (iVar1 == *(int*)(puVar2 + 0x178))) break;
        iVar4 = iVar3 + 2;
        if ((*(int*)(puVar2 + 0x188) == 0) || (iVar1 == *(int*)(puVar2 + 0x188))) break;
        iVar4 = iVar3 + 3;
        if ((*(int*)(puVar2 + 0x198) == 0) || (iVar1 == *(int*)(puVar2 + 0x198))) break;
        iVar4 = iVar3 + 4;
        if ((*(int*)(puVar2 + 0x1a8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1a8))) break;
        iVar4 = iVar3 + 5;
        if ((*(int*)(puVar2 + 0x1b8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1b8))) break;
        iVar4 = iVar3 + 6;
        if ((*(int*)(puVar2 + 0x1c8) == 0) || (iVar1 == *(int*)(puVar2 + 0x1c8))) break;
        puVar2 = puVar2 + 0x70;
        iVar3 = iVar3 + 7;
        iVar5 = iVar5 + -1;
        iVar4 = iVar3;
        if (iVar5 == 0) break;
    }
    if (iVar4 == 0x3f)
    {
        return;
    }
    (&DAT_803a4070)[iVar4 * 4] = *(undefined4*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    (&DAT_803a4074)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosX;
    (&DAT_803a4078)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosY;
    (&DAT_803a407c)[iVar4 * 4] = *(undefined4*)&((GameObject*)param_1)->anim.localPosZ;
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

void FUN_800e95e8(undefined4 param_1, undefined4 param_2, int param_3)
{
    bool bVar1;
    char cVar2;
    uint uVar3;
    char cVar4;
    short* psVar5;
    char* pcVar6;
    uint* puVar7;
    uint uVar8;
    uint uVar9;
    uint uVar10;
    char* pcVar11;
    int iVar12;
    int iVar13;
    longlong lVar14;

    lVar14 = FUN_80286830();
    uVar10 = (uint)((ulonglong)lVar14 >> 0x20);
    uVar8 = (uint)lVar14;
    pcVar11 = &DAT_803a3be0;
    if (0x4fffffffff < lVar14)
    {
        uVar10 = (uint)(byte)(&DAT_803a3dac)[uVar10];
    }
    if ((int)uVar10 < 0x78)
    {
        if ((ushort)(&DAT_80312460)[uVar10] != 0)
        {
            if (param_3 == -1)
            {
                param_3 = 1;
            }
            bVar1 = param_3 == -2;
            if (bVar1)
            {
                param_3 = 0;
            }
            uVar3 = FUN_80017690((uint)(ushort)(&DAT_80312460)[uVar10]);
            if (param_3 == 0)
            {
                uVar9 = uVar3 & ~(1 << uVar8);
            }
            else
            {
                uVar9 = uVar3 | 1 << uVar8;
            }
            FUN_80017698((uint)(ushort)(&DAT_80312460)[uVar10], uVar9);
            DAT_803de104 = uVar10;
            uRam803de108 = uVar9;
            if (param_3 == 0)
            {
                psVar5 = &DAT_80312460;
                puVar7 = &DAT_803a3c1c;
                uVar3 = ~(1 << uVar8);
                iVar12 = 0x14;
                do
                {
                    if (*psVar5 == (&DAT_80312460)[uVar10])
                    {
                        *puVar7 = *puVar7 & uVar3;
                    }
                    if (psVar5[1] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[1] = puVar7[1] & uVar3;
                    }
                    if (psVar5[2] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[2] = puVar7[2] & uVar3;
                    }
                    if (psVar5[3] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[3] = puVar7[3] & uVar3;
                    }
                    if (psVar5[4] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[4] = puVar7[4] & uVar3;
                    }
                    if (psVar5[5] == (&DAT_80312460)[uVar10])
                    {
                        puVar7[5] = puVar7[5] & uVar3;
                    }
                    psVar5 = psVar5 + 6;
                    puVar7 = puVar7 + 6;
                    iVar12 = iVar12 + -1;
                }
                while (iVar12 != 0);
                if (!bVar1)
                {
                    cVar4 = '\0';
                    iVar12 = 4;
                    pcVar6 = pcVar11;
                    do
                    {
                        if ((((((uVar10 == (int)*pcVar6) && (cVar2 = cVar4, uVar8 == (byte)pcVar6[1])) ||
                                    ((cVar2 = cVar4 + '\x01', uVar10 == (int)pcVar6[3] && (uVar8 == (byte)pcVar6[4])))
                                ) || ((cVar2 = cVar4 + '\x02', uVar10 == (int)pcVar6[6] &&
                                    (uVar8 == (byte)pcVar6[7])))) ||
                                ((cVar2 = cVar4 + '\x03', uVar10 == (int)pcVar6[9] && (uVar8 == (byte)pcVar6[10]))))
                            || ((uVar10 == (int)pcVar6[0xc] &&
                                (cVar2 = cVar4 + '\x04', uVar8 == (byte)pcVar6[0xd]))))
                            goto LAB_800e9628;
                        pcVar6 = pcVar6 + 0xf;
                        cVar4 = cVar4 + '\x05';
                        iVar12 = iVar12 + -1;
                    }
                    while (iVar12 != 0);
                    cVar2 = -1;
                LAB_800e9628:
                    if (cVar2 == -1)
                    {
                        iVar12 = 0;
                        iVar13 = 0x14;
                        do
                        {
                            if (*pcVar11 == -1)
                            {
                                iVar12 = iVar12 * 3;
                                (&DAT_803a3be0)[iVar12] = (char)uVar10;
                                (&DAT_803a3be1)[iVar12] = (char)lVar14;
                                (&DAT_803a3be2)[iVar12] = 3;
                                break;
                            }
                            pcVar11 = pcVar11 + 3;
                            iVar12 = iVar12 + 1;
                            iVar13 = iVar13 + -1;
                        }
                        while (iVar13 != 0);
                    }
                }
            }
            else
            {
                uVar8 = 1 << uVar8;
                if ((uVar3 & uVar8) == 0)
                {
                    psVar5 = &DAT_80312460;
                    puVar7 = &DAT_803a3c1c;
                    iVar12 = 0x14;
                    do
                    {
                        if (*psVar5 == (&DAT_80312460)[uVar10])
                        {
                            *puVar7 = *puVar7 | uVar8;
                        }
                        if (psVar5[1] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[1] = puVar7[1] | uVar8;
                        }
                        if (psVar5[2] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[2] = puVar7[2] | uVar8;
                        }
                        if (psVar5[3] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[3] = puVar7[3] | uVar8;
                        }
                        if (psVar5[4] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[4] = puVar7[4] | uVar8;
                        }
                        if (psVar5[5] == (&DAT_80312460)[uVar10])
                        {
                            puVar7[5] = puVar7[5] | uVar8;
                        }
                        psVar5 = psVar5 + 6;
                        puVar7 = puVar7 + 6;
                        iVar12 = iVar12 + -1;
                    }
                    while (iVar12 != 0);
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
    undefined* puVar2;
    short sVar3;
    uint uVar4;
    uint uVar5;
    uint uVar6;
    uint unaff_r27;
    uint uVar7;
    uint uVar8;
    short* psVar9;

    uVar1 = FUN_80286834();
    puVar2 = FUN_800e82d8();
    uVar7 = 0xffffffff;
    if (puVar2[6] == '\0')
    {
        psVar9 = &DAT_80312632;
        for (uVar8 = 1; (short)uVar8 < 0xce; uVar8 = uVar8 + 1)
        {
            if ((*psVar9 == 0xffff) || (*psVar9 == -1))
            {
                uVar5 = 1 << (uVar8 & 0x1f);
                uVar6 = (uint)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
                uVar4 = FUN_80017690(uVar6);
                if ((uVar4 & uVar5) == 0)
                {
                    FUN_80017698(uVar6, uVar4 | uVar5);
                }
            }
            psVar9 = psVar9 + 1;
        }
    }
    uVar6 = 1 << (uVar1 & 0x1f);
    uVar4 = (uint)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
    uVar8 = FUN_80017690(uVar4);
    if ((uVar8 & uVar6) == 0)
    {
        FUN_80017698(uVar4, uVar8 | uVar6);
        if (puVar2[6] != '\x05')
        {
            puVar2[6] = puVar2[6] + '\x01';
        }
        for (sVar3 = 4; sVar3 != 0; sVar3 = sVar3 + -1)
        {
            puVar2[sVar3] = puVar2[sVar3 + -1];
        }
        *puVar2 = (char)uVar1;
        if ((uint)(byte)puVar2[5] == (uVar1 & 0xff)
        )
        {
            do
            {
                puVar2[5] = puVar2[5] + '\x01';
                uVar1 = (uint)(short)(((byte)puVar2[5] >> 5) + 0x12f);
                if (uVar1 != (int)(short)uVar7)
                {
                    unaff_r27 = FUN_80017690(uVar1);
                    uVar7 = uVar1;
                }
            }
            while ((unaff_r27 & 1 << ((byte)puVar2[5] & 0x1f)) != 0);
        }
    }
    FUN_80286880();
    return;
}

void SaveGame_func08_nop(void);

void dll_65_func01_nop(void)
{
}

void dll_65_func00_nop(void)
{
}

void dll_A3_func01_nop(void);

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

void dll_65_func03(int sourceObj, int variant, int posSource, uint flags)
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
    int ctx;
    u8 cnt;
    if (variant == 1)
    {
        *(s16*)&lbl_80312E58[274] = 0;
    }
    cnt = *(u8*)(*(int*)(sourceObj + 76) + 26);
    e[0].layer = 0;
    e[0].flags = 7;
    e[0].tex = &lbl_80312E58[240];
    e[0].mode = 8;
    e[0].x = lbl_803E0930;
    e[0].y = lbl_803E0930;
    e[0].z = lbl_803E0930;
    e[1].layer = 0;
    e[1].flags = 7;
    e[1].tex = &lbl_80312E58[256];
    e[1].mode = 8;
    e[1].x = lbl_803E0934;
    e[1].y = lbl_803E0934;
    e[1].z = lbl_803E0934;
    e[2].layer = 0;
    e[2].flags = 0xe;
    e[2].tex = &lbl_80312E58[212];
    e[2].mode = 4;
    e[2].x = lbl_803E0938;
    e[2].y = lbl_803E0938;
    e[2].z = lbl_803E0938;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &lbl_80312E58[256];
    e[3].mode = 2;
    e[3].x = lbl_803E093C;
    e[3].y = lbl_803E0940;
    e[3].z = lbl_803E093C;
    e[4].layer = 0;
    e[4].flags = 7;
    e[4].tex = &lbl_80312E58[240];
    e[4].mode = 2;
    e[4].x = lbl_803E0944;
    e[4].y = lbl_803E0948;
    e[4].z = lbl_803E0944;
    e[5].layer = 1;
    e[5].flags = 0x12;
    e[5].tex = &lbl_80312E58[212];
    e[5].mode = 0x100;
    e[5].x = lbl_803E0938;
    e[5].y = lbl_803E0938;
    e[5].z = lbl_803E094C;
    e[6].layer = 1;
    e[6].flags = 7;
    e[6].tex = &lbl_80312E58[240];
    e[6].mode = 4;
    e[6].x = lbl_803E0950;
    e[6].y = lbl_803E0938;
    e[6].z = lbl_803E0938;
    e[7].layer = 1;
    e[7].flags = 7;
    e[7].tex = &lbl_80312E58[256];
    e[7].mode = 4;
    e[7].x = lbl_803E0954;
    e[7].y = lbl_803E0938;
    e[7].z = lbl_803E0938;
    e[8].layer = 2;
    e[8].flags = 0x12;
    e[8].tex = &lbl_80312E58[212];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0958;
    e[8].y = lbl_803E0938;
    e[8].z = lbl_803E0938;
    e[9].layer = 3;
    e[9].flags = 1;
    e[9].tex = (void*)0;
    e[9].mode = 0x2000;
    e[9].x = lbl_803E0938;
    e[9].y = lbl_803E0938;
    e[9].z = lbl_803E0938;
    e[10].layer = 4;
    e[10].flags = 7;
    e[10].tex = &lbl_80312E58[240];
    e[10].mode = 4;
    e[10].x = lbl_803E0938;
    e[10].y = lbl_803E0938;
    e[10].z = lbl_803E0938;
    e[11].layer = 4;
    e[11].flags = 7;
    e[11].tex = &lbl_80312E58[256];
    e[11].mode = 4;
    e[11].x = lbl_803E0938;
    e[11].y = lbl_803E0938;
    e[11].z = lbl_803E0938;
    e[12].layer = 4;
    e[12].flags = 0x12;
    e[12].tex = &lbl_80312E58[212];
    e[12].mode = 0x4000;
    e[12].x = lbl_803E0958;
    e[12].y = lbl_803E0938;
    e[12].z = lbl_803E0938;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0958;
    buf.pos[1] = lbl_803E0958;
    buf.pos[2] = lbl_803E0958;
    buf.col[0] = lbl_803E0938;
    buf.col[1] = lbl_803E0938;
    buf.col[2] = lbl_803E0938;
    if (cnt != 0)
    {
        buf.scale = lbl_803E095C * (f32)(u32)cnt;
    }
    else
    {
        buf.scale = lbl_803E0960;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 13;
    buf.hw[0] = *(s16*)&lbl_80312E58[272];
    buf.hw[1] = *(s16*)&lbl_80312E58[274];
    buf.hw[2] = *(s16*)&lbl_80312E58[276];
    buf.hw[3] = *(s16*)&lbl_80312E58[278];
    buf.hw[4] = *(s16*)&lbl_80312E58[280];
    buf.hw[5] = *(s16*)&lbl_80312E58[282];
    buf.hw[6] = *(s16*)&lbl_80312E58[284];
    buf.cmds = buf.entries;
    buf.flags = 0x40000c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (ctx == 0)
        {
            buf.pos[0] = lbl_803E0958 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0958 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0958 + ((PartFxSpawnParams*)posSource)->posZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0958 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0958 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0958 + *(f32*)(ctx + 0x20);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, &lbl_80312E58[0], 0xc, &lbl_80312E58[140], 0x40, 0);
}

void dll_66_func03(int sourceObj, int variant, int posSource, uint flags);

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, uint flags);
