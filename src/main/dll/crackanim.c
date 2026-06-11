#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/crackanim_state.h"
#include "main/dll/baddie_state.h"
#include "main/dll/crackanim.h"

typedef struct AppleontreeObjectDef
{
    u8 pad0[0x18 - 0x0];
    u32 unk18;
    u16 duration;
    u16 elapsed;
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 unk24;
    s8 unk25;
    s16 unk26;
} AppleontreeObjectDef;


extern undefined8 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017a78();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern int ObjMsg_Pop();
extern undefined4 FUN_80039520();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8017db40();
extern undefined4 FUN_8017de58();
extern int FUN_8017e15c();
extern int FUN_8017e3c0();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294d60();

extern u8* Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void playerAddHealth(u8* player, int v);
extern void itemPickupDoParticleFx(int obj, f32 f1, int p3, int p4);
extern u32 randomGetRange(int min, int max);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern int* objFindTexture(int obj, int textureId, int modelIdx);

extern undefined4* gSHthorntailAnimationInterface;
extern EffectInterface** gPartfxInterface;
extern f64 lbl_803E3820;
extern f32 timeDelta;
extern f32 lbl_803E37C8;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37DC;
extern f32 lbl_803E3828;
extern f32 lbl_803E382C;
extern f32 lbl_803E3830;
extern f32 lbl_803E3834;
extern f32 lbl_803E3838;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3814;
extern f32 lbl_803E3818;

/*
 * --INFO--
 *
 * Function: appleontree_update
 * EN v1.0 Address: 0x8017E1A0
 * EN v1.0 Size: 2460b
 * EN v1.1 Address: 0x8017E6F8
 * EN v1.1 Size: 1988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_update(int param_1)
{
    float fa;
    undefined2* obj;
    int val;
    undefined4* wordPtr2;
    uint bitVal;
    int* wordPtr;
    int placement;
    int state;
    f32 fc;
    f32 fb;
    f32 fd;
    f32 frac;
    int msg;
    undefined msgExtra[4];

    obj = (undefined2*)param_1;
    state = *(int*)(obj + 0x5c);
    placement = *(int*)(obj + 0x26);
    msg = 0;
    if ((*(byte*)(state + 0x5a) & 4) != 0)
    {
        while (val = ObjMsg_Pop((int)obj, &msg, (uint*)0x0, (uint*)0x0), val != 0)
        {
            switch (msg)
            {
            case 0x7000b:
                {
                    playerAddHealth(Obj_GetPlayerObject(), (int)*(u16*)(state + 0x38));
                    itemPickupDoParticleFx((int)obj, lbl_803E37C8, 0xff, 0x28);
                    Sfx_PlayFromObject((int)obj, SFXen_waterblock_stop);
                    val = *(int*)(obj + 0x5c);
                    if (((GameObject*)obj)->anim.flags & 0x2000)
                    {
                        Obj_FreeObject((int)obj);
                    }
                    else
                    {
                        if (*(void**)(obj + 0x2a) != 0)
                        {
                            ObjHits_DisableObject((int)obj);
                        }
                        *(byte*)(val + 0x5a) = *(byte*)(val + 0x5a) | 2;
                    }
                    *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) & ~4;
                }
            }
        }
        if ((*(byte*)(state + 0x5a) & 4) != 0) goto switchD_8017e864_caseD_7;
    }
    if ((*(byte*)(state + 0x5a) & 2) == 0)
    {
        *(float*)(state + 8) = *(float*)(state + 8) + timeDelta;
        fa = *(float*)(state + 0xc);
        *(float*)(state + 0xc) = fa + timeDelta;
        fb = *(float*)(state + 8);
        frac = fb / *(float*)(state + 4);
        switch (*(undefined*)(state + 0x3a))
        {
        case 0:
            val = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)(obj + 0x5c);
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 2;
                *(float*)(state + 8) = timeDelta;
                *(undefined*)(state + 0x3a) = 5;
            }
            else
            {
                if (frac > *(float*)(state + 0x10))
                {
                    *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4);
                    *(undefined*)(state + 0x3a) = 1;
                }
                else
                {
                    placement = *(int*)(obj + 0x5c);
                    *(float*)(obj + 4) =
                        (*(float*)(placement + 8) / *(float*)(placement + 4)) *
                        (lbl_803E37C8 / *(float*)(placement + 0x10)) *
                        *(float*)(*(int*)(obj + 0x28) + 4);
                }
            }
            break;
        case 1:
            val = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)(obj + 0x5c);
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 2;
                *(float*)(state + 8) = timeDelta;
                *(undefined*)(state + 0x3a) = 5;
            }
            else
            {
                if (frac > ((GroundBaddieState*)state)->baddie.posX)
                {
                    placement = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                        placement = placement + 1;
                    }
                    while (placement < 8);
                    *(undefined*)(state + 0x3a) = 2;
                }
                else
                {
                    placement = (*(int (**)(void*))(*gSHthorntailAnimationInterface + 0x24))(msgExtra);
                    if (placement != 0)
                    {
                        FUN_8002fc3c(lbl_803E3804, timeDelta);
                    }
                    else
                    {
                        FUN_8002fc3c(lbl_803E3808, timeDelta);
                    }
                }
            }
            break;
        case 2:
            if (frac > ((GroundBaddieState*)state)->baddie.posY)
            {
                val = *(int*)(obj + 0x5c);
                wordPtr2 = (undefined4*)FUN_80039520((int)obj, 0);
                *wordPtr2 = 0;
                *(float*)(val + 0x24) = lbl_803E37C8;
                *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4);
                FUN_80017a78((int)obj, 1);
                *(undefined*)(state + 0x3a) = 3;
            }
            else
            {
                val = *(int*)(obj + 0x5c);
                fa = *(float*)(val + 8);
                fb = -(*(float*)(val + 4) * *(float*)(val + 0x14) - fa) /
                (*(float*)(val + 4) *
                    (*(float*)(val + 0x18) - *(float*)(val + 0x14)));
                fa = fa * fa * fa * fa;
                state = (int)((fa * fa) / *(float*)(val + 0x54));
                wordPtr = (int*)FUN_80039520((int)obj, 0);
                *wordPtr = 0x100 - state;
                *(float*)(val + 0x24) = lbl_803E37D0 * fb + lbl_803E37CC;
                *(float*)(obj + 4) = *(float*)(*(int*)(obj + 0x28) + 4) * *(float*)(val + 0x24);
                FUN_80017a78((int)obj, 1);
            }
            state = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
            if ((state != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                FUN_8017db40((uint)obj, 1);
            }
            break;
        case 3:
            *(float*)(state + 8) = fb - timeDelta;
            if (frac > ((GroundBaddieState*)state)->baddie.posZ)
            {
                FUN_8017db40((uint)obj, 0);
            }
            else
            {
                state = ObjHits_GetPriorityHit((int)obj, (undefined4*)0x0, (int*)0x0, (uint*)0x0);
                if ((state != 0) ||
                    ((*(short*)(placement + 0x26) != -1 &&
                        (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
                {
                    FUN_8017db40((uint)obj, 2);
                }
            }
            break;
        case 4:
            if (frac > *(float*)(state + 0x20))
            {
                *(undefined*)(state + 0x3a) = 6;
                *(float*)(state + 8) = timeDelta;
            }
            else
            {
                placement = 0;
                val = 0;
                fd = lbl_803E37D4;
                do
                {
                    f32 t = *(float*)(state + 0xc);
                    if (placement != 0) break;
                    fb = t * (((GroundBaddieState*)state)->baddie.velZ + ((GroundBaddieState*)state)->baddie.velY);
                    fc = t * fb + (*(float*)(state + 0x44) * t + *(float*)(state + 0x2c));
                    if (*(float*)(state + 0x28) <= fd)
                    {
                        placement = FUN_8017e15c(fc, obj, state);
                    }
                    else
                    {
                        placement = FUN_8017e3c0(fc, obj, state);
                    }
                    val = val + 1;
                }
                while ((val == 100) || (val != 0x66));
                if (lbl_803E37D4 != *(float*)(state + 0x30))
                {
                    fb = *(float*)(state + 0xc) / *(float*)(state + 0x50);
                    *obj = (f32) * (s16*)(state + 0x48) * fb;
                    obj[1] = (f32) * (s16*)(state + 0x4a) * fb;
                    obj[2] = (f32) * (s16*)(state + 0x4c) * fb;
                }
                wordPtr = (int*)FUN_80039520((int)obj, 0);
                *wordPtr = (int)(lbl_803E380C * frac);
                FUN_8017de58((uint)obj);
            }
            break;
        case 5:
            if (lbl_803E3810 < fb)
            {
                placement = *(int*)(obj + 0x5c);
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(byte*)(placement + 0x5a) = *(byte*)(placement + 0x5a) | 2;
                }
            }
            break;
        case 6:
            frac = lbl_803E3814;
            if (fb > frac)
            {
                placement = *(int*)(obj + 0x5c);
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(byte*)(placement + 0x5a) = *(byte*)(placement + 0x5a) | 2;
                }
            }
            else
            {
                placement = (int)(lbl_803E3818 * fb / frac);
                *(char*)(obj + 0x1b) = -1 - (char)placement;
                FUN_8017de58((uint)obj);
            }
        }
    }
switchD_8017e864_caseD_7:
    return;
}

/*
 * --INFO--
 *
 * Function: appleontree_init
 * EN v1.0 Address: 0x8017E964
 * EN v1.0 Size: 684b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_init(int obj, int def)
{
    int state;
    f32 zeroScale;
    f32 timeScale;
    f32 progress;
    int eventBit;
    int* texture;

    state = *(int*)&((GameObject*)obj)->extra;

    ((CrackAnimState*)state)->unk0 = ((AppleontreeObjectDef*)def)->unk18;
    ((CrackAnimState*)state)->duration = (f32)((AppleontreeObjectDef*)def)->duration;
    ((CrackAnimState*)state)->elapsed = (f32)((AppleontreeObjectDef*)def)->elapsed;
    {
        f32 scale = lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd0 = (f32)((AppleontreeObjectDef*)def)->unk20 / scale;
        ((CrackAnimState*)state)->stageEnd1 = ((CrackAnimState*)state)->stageEnd0 + (f32)((AppleontreeObjectDef*)def)->
            unk21 / scale;
        ((CrackAnimState*)state)->stageEnd2 = ((CrackAnimState*)state)->stageEnd1 + (f32)((AppleontreeObjectDef*)def)->
            unk22 / scale;
        ((CrackAnimState*)state)->stageEnd3 = ((CrackAnimState*)state)->stageEnd2 + (f32)((AppleontreeObjectDef*)def)->
            unk23 / scale;
        ((CrackAnimState*)state)->unk20 = (f32)((AppleontreeObjectDef*)def)->unk24 / scale;
        ((CrackAnimState*)state)->unk28 = (f32)((AppleontreeObjectDef*)def)->unk25 / scale;
        ((CrackAnimState*)state)->unk28 = ((CrackAnimState*)state)->unk28 * lbl_803E37DC;
        ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
        ((CrackAnimState*)state)->unk38 = 0;
        zeroScale = lbl_803E37D4;
        ((CrackAnimState*)state)->unk3C = zeroScale;
        ((CrackAnimState*)state)->unk40 = lbl_803E382C;
        ((CrackAnimState*)state)->unk44 = zeroScale;

        timeScale = ((CrackAnimState*)state)->duration * ((CrackAnimState*)state)->stageEnd2;
        timeScale *= timeScale;
        timeScale *= timeScale;
        ((CrackAnimState*)state)->unk54 = (timeScale * timeScale) * lbl_803E3830;

        ((GameObject*)obj)->anim.rotX = (s16)randomGetRange(-0x8000, 0x7fff);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3834;
        Obj_SetActiveModelIndex(obj, 0);

        eventBit = ((AppleontreeObjectDef*)def)->unk26;
        if ((eventBit != -1) && (GameBit_Get(eventBit) != 0))
        {
            ((CrackAnimState*)state)->elapsed = lbl_803E3838;
            ((CrackAnimState*)state)->stage = 6;
        }
        else
        {
            progress = ((CrackAnimState*)state)->elapsed / ((CrackAnimState*)state)->duration;
            if (progress < ((CrackAnimState*)state)->stageEnd0)
            {
                ((CrackAnimState*)state)->stage = 0;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd1)
            {
                ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                ((CrackAnimState*)state)->stage = 1;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd2)
            {
                ((CrackAnimState*)state)->stage = 2;
            }
            else
            {
                state = *(int*)&((GameObject*)obj)->extra;
                texture = objFindTexture(obj, 0, 0);
                *texture = 0;
                ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                Obj_SetActiveModelIndex(obj, 1);
                ((CrackAnimState*)state)->stage = 3;
            }
        }

        ObjMsg_AllocQueue(obj, 2);
    }
}

/* Trivial 4b 0-arg blr leaves. */
void dll_FC_free_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int dll_FC_getExtraSize_ret_8(void) { return 0x8; }
int dll_FC_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3848;
extern void objRenderFn_8003b8f4(f32);

void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3848);
}

extern void dll_FC_initialise_nop(void);
extern void dll_FC_release_nop(void);
extern void dll_FC_init(void);
extern void dll_FC_update(void);
extern void dll_FC_hitDetect(int* obj);

extern void objRenderFn_80041018(int* obj);

void dll_FC_hitDetect(int* obj)
{
    int* state = (int*)obj[0x50 / 4];
    if (((u32)state[0x44 / 4] & 1u) == 0u) return;
    if (*(void**)((char*)obj + 0x74) == NULL) return;
    objRenderFn_80041018(obj);
}

ObjectDescriptor gDllFCObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};
