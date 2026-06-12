#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"





typedef struct InfopointObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    s16 unk1C;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;




















extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;


/*
 * --INFO--
 *
 * Function: FUN_80187664
 * EN v1.0 Address: 0x80187664
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x80187720
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: infopoint_hitDetect
 * EN v1.0 Address: 0x8018843C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801884A0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void infopoint_hitDetect(void)
{
}


/*
 * --INFO--
 *
 * Function: FUN_80189054
 * EN v1.0 Address: 0x80189054
 * EN v1.0 Size: 2620b
 * EN v1.1 Address: 0x80189218
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , int param_11, int param_12, undefined4 param_13, undefined4 param_14, undefined4 param_15,
             undefined4 param_16)
{
    undefined4 uVar1;
    char cVar2;
    int iVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    int iVar7;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 uVar8;

    iVar6 = *(int*)&((GameObject*)param_9)->anim.placementData;
    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    iVar7 = 0;
    iVar4 = param_11;
    do
    {
        if ((int)(uint) * (byte*)(param_11 + 0x8b) <= iVar7)
        {
            return 0;
        }
        switch (*(u8*)(param_11 + iVar7 + 0x81))
        {
        case 2:
        case 0x65:
            iVar4 = *(int*)(iVar6 + 0x14);
            if (iVar4 == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x26);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else if (iVar4 < 0x49f5a)
            {
                if (iVar4 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1;
                    if (cVar2 == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0xb);
                        FUN_80042bec(uVar1, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0x29);
                        FUN_80042bec(uVar1, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    uVar1 = FUN_80044404(0x29);
                    FUN_80042bec(uVar1, 0);
                }
            }
            else if (iVar4 == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x41);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x29);
                FUN_80042bec(uVar1, 0);
            }
            break;
        case 3:
        case 100:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                iVar4 = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (iVar3 < 0x49f5a)
            {
                if (iVar3 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1_00;
                    if (cVar2 == '\x02')
                    {
                        uVar8 = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setAnimEvent(0xd, 10, 0);
                        (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 0);
                        iVar4 = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775))
                {
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_01;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_02;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
            }
            else if (iVar3 < 0x49f5a)
            {
                if ((iVar3 == 0x451b9) &&
                    (cVar2 = (*gMapEventInterface)->getMode(0xd), param_1 = extraout_f1_03,
                        cVar2 == '\x02'))
                {
                    iVar4 = (int)*gMapEventInterface;
                    uVar8 = (**(code**)(iVar4 + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', iVar4
                             , param_12, param_13, param_14, param_15, param_16);
                iVar4 = (int)*gMapEventInterface;
                param_1 = (**(code**)(iVar4 + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(iVar5 + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(iVar5 + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(iVar5 + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(iVar5 + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(iVar5 + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(iVar5 + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(iVar5 + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(iVar5 + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(iVar5 + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(iVar5 + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) & 0xbfff;
            }
            break;
        case 0x19:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) | 0x4000;
            }
        }
        iVar7 = iVar7 + 1;
    }
    while (true);
}


/* Trivial 4b 0-arg blr leaves. */
void flammablevine_release(void);









void infopoint_free(void)
{
}

void infopoint_release(void)
{
}

void infopoint_initialise(void)
{
}

void decoration11a_free(void);


/* 8b "li r3, N; blr" returners. */
int infopoint_getExtraSize(void) { return 0x20; }
int infopoint_getObjectTypeId(void) { return 0x0; }
int decoration11a_getExtraSize(void);




/* Carryable impact state machine that spawns break particles, hides, then respawns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3B70;


#pragma scheduling off
#pragma peephole off
void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3B70);
}

void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* ObjGroup_RemoveObject(x, N) wrappers. */




/* Fall_Ladders_free: expgfx interface freeObject callback. */

/* coldwatercontrol_init: set float field + OR flag bits. */


/* landed_arwing_free: free child object + detach link. */

/* landed_arwing_render: visible-guarded render with extra call. */













/* infopoint_update: if low bit on 0xaf, disable button + vtable[0x48]. */
extern void buttonDisable(int p1, int mask);

void infopoint_update(int obj)
{
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
    {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
}

/* landed_arwing_init: flag bits, counter, conditional unlock, set callback. */
void landed_arwing_init(int obj, int param);


/* landed arwing hit/animation step: handles impact reactions and spawned debris. */

/* landed arwing material flags: mirrors game bits into the damaged texture state. */


#pragma dont_inline on
#pragma dont_inline reset

int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    s16* inner = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1: inner[0xb] = (s16)0xff;
            break;
        case 2: inner[0xb] = 0;
            break;
        case 3: break;
        case 4: break;
        }
    }
    return 0;
}

void dll_109_free(int obj);





extern int textureLoadAsset(int id);
extern int* gameTextGet(int id);
extern int lbl_803219A0[];
extern int lbl_80321990[];

void infopoint_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    int* txt;
    ((GameObject*)obj)->animEventCallback = (void*)InfoPoint_SeqFn;
    if (*(void**)lbl_803219A0 == NULL)
    {
        *(int*)lbl_803219A0 = textureLoadAsset(616);
    }
    *(int*)(state + 8) = (int)lbl_80321990;
    txt = gameTextGet(((InfopointObjectDef*)def)->unk18);
    *(int*)(state + 4) = **(int**)((char*)txt + 8);
    *(int*)(state + 0xc) = 100;
    *(int*)state = (int)txt;
    *(s16*)obj = (s16)((s32) * (u8*)((char*)def + 0x1c) << 8);
    *(int*)(state + 0x18) = 2;
    *(u8*)(state + 0x10) = ((InfopointObjectDef*)def)->unk1B;
    *(s16*)(state + 0x16) = 0;
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

extern f32 lbl_803E3B7C;


