#include "main/dll/alphaanim.h"
#include "main/dll/appleontreestate_struct.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/groundanimator_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/groundAnimator.h"

extern uint GameBit_Get(int eventId);
extern undefined8 ObjGroup_RemoveObject();

extern f32 lbl_803E37B0;
extern undefined8 FUN_80006824();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632d8();
extern undefined4 FUN_80081118();
extern double FUN_80293900();
extern undefined4 FUN_80294d60();
extern void GameBit_Set(int eventId, int value);
extern undefined4* DAT_803dd718;
extern f32 lbl_803DC074;
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4488;
extern f32 lbl_803E448C;
extern f32 lbl_803E4490;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;
extern void appleontree_init();
extern void appleontree_update();
extern void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
extern void appleontree_free(int* obj);
extern int appleontree_getExtraSize(void);
extern void appleontree_setScale(void);
extern u8 appleontree_modelMtxFn(int* obj);
STATIC_ASSERT(offsetof(AppleOnTreeState, healthRestore) == 0x38);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk50) == 0x50);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk60) == 0x60);
STATIC_ASSERT(sizeof(AppleOnTreeState) == 0x64);

void dll_115_hitDetect_nop(void)
{
}

int dll_115_getExtraSize_ret_2(void) { return 0x2; }
int dll_115_getObjectTypeId(void) { return 0x0; }

void dll_115_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32); /* #57 */
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E37B0);
}

void dll_115_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */

int dll_115_seqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    int v;
    u8* state = ((GameObject*)obj)->extra;
    s16* def = *(s16**)&((GameObject*)obj)->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    {
        v = state[0];
        if (v >= 10 || v < 8)
        {
            int n = v + 1;
            if (n < 8)
            {
                s16 newId = (def + n)[0x14];
                if (newId != -1 && newId != (def + v)[0x14])
                {
                    if (GameBit_Get(newId) != 0)
                    {
                        (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
                    }
                }
            }
        }
    }
    state[1] = (u8)(state[1] | 1);
    return 0;
}

typedef struct Dll115Placement
{
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    s8 unk19;
    u8 pad1A[0x38 - 0x1A];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} Dll115Placement;


void dll_115_update(int obj)
{
    u8* state;
    u8* mapData;
    short* p;
    int step;
    int eventId;

    state = ((GameObject*)obj)->extra;
    mapData = (u8*)((GameObject*)obj)->anim.placementData;
    if ((state[1] & 1) != 0)
    {
        eventId = ((s16*)(mapData + 0x18))[state[0]];
        if (eventId != -1)
        {
            GameBit_Set(eventId, 1);
        }
        state[1] = (u8)(state[1] & ~1);
        state[0]++;
    }
    switch (state[0])
    {
    case 9:
        (*gObjectTriggerInterface)->preempt(obj, ((Dll115Placement*)mapData)->unk3C);
        (*gObjectTriggerInterface)->runSequence(((Dll115Placement*)mapData)->unk3A, (void*)obj,
                                                ((Dll115Placement*)mapData)->unk3B);
        break;
    case 8:
    case 10:
        break;
    default:
        eventId = ((s16*)(mapData + 0x28))[state[0]];
        if (eventId == -1)
        {
            state[0] = 8;
        }
        else if ((u32)GameBit_Get(eventId) != 0)
        {
            s8 id = (s8)((u8*)(mapData + 0x40))[state[0]];
            if (id != -1)
            {
                (*gObjectTriggerInterface)->runSequence(id, (void*)obj, -1);
            }
        }
        break;
    }
    {
        step = state[0] - 1;
        p = (short*)mapData + step;
        while (step >= 0)
        {
            eventId = p[12];
            if (eventId == -1) break;
            if ((u32)GameBit_Get(eventId) != 0) break;
            state[0]--;
            p--;
            step--;
        }
    }
}

void dll_115_init(short* obj, int mapData)
{
    short* p;
    u8* state;
    int step;

    state = ((GameObject*)obj)->extra;
    *obj = (s16)(*(u8*)(mapData + 0x38) << 8);
    ((GameObject*)obj)->animEventCallback = dll_115_seqFn;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ObjGroup_AddObject((int)obj, 0xf);
    step = 0;
    p = (short*)mapData;
    do
    {
        if (p[12] == -1) break;
        if ((u32)GameBit_Get(p[12]) == 0) break;
        p++;
        step++;
    }
    while (step < 8);
    if ((step < 8) && (*(s16*)(mapData + 0x18 + step * 2) == -1))
    {
        state[0] = 8;
    }
    else
    {
        state[0] = step;
    }
    if ((state[0] == 8) && ((*(u8*)(mapData + 0x39) & 0x10) != 0))
    {
        state[0] = 9;
    }
}

void dll_115_release_nop(void)
{
}

void dll_115_initialise_nop(void)
{
}









ObjectDescriptor gWM_ColumnObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wm_column_initialise,
    (ObjectDescriptorCallback)wm_column_release,
    0,
    (ObjectDescriptorCallback)wm_column_init,
    (ObjectDescriptorCallback)wm_column_update,
    (ObjectDescriptorCallback)wm_column_hitDetect,
    (ObjectDescriptorCallback)wm_column_render,
    (ObjectDescriptorCallback)wm_column_free,
    (ObjectDescriptorCallback)wm_column_getObjectTypeId,
    wm_column_getExtraSize,
};

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)appleontree_init,
    (ObjectDescriptorCallback)appleontree_update,
    0,
    (ObjectDescriptorCallback)appleontree_render,
    (ObjectDescriptorCallback)appleontree_free,
    0,
    appleontree_getExtraSize,
    (ObjectDescriptorCallback)appleontree_setScale,
    (ObjectDescriptorCallback)appleontree_func0B,
    (ObjectDescriptorCallback)appleontree_modelMtxFn,
};

u32 jumptable_803214DC[] = {
    (u32)((u8*)appleontree_update + 0x170),
    (u32)((u8*)appleontree_update + 0x274),
    (u32)((u8*)appleontree_update + 0x3C4),
    (u32)((u8*)appleontree_update + 0x4E8),
    (u32)((u8*)appleontree_update + 0x554),
    (u32)((u8*)appleontree_update + 0x6C8),
    (u32)((u8*)appleontree_update + 0x71C),
};

#pragma scheduling on
#pragma peephole on
void FUN_8017db40(uint param_1, int param_2)
{
    undefined2 mode;
    uint rnd;
    int groundResult;
    int state;
    double px;
    double py;
    double pz;
    undefined8 in_f4;
    double tmp;
    undefined8 in_f5;
    undefined8 in_f6;
    undefined8 in_f7;
    undefined8 in_f8;

    state = *(int*)&((GameObject*)param_1)->extra;
    if (param_2 == 1)
    {
        mode = 2;
    }
    else
    {
        if (param_2 < 1)
        {
            if (-1 < param_2)
            {
                mode = 2;
                goto LAB_8017de10;
            }
        }
        else if (param_2 < 3)
        {
            mode = 2;
            goto LAB_8017de10;
        }
        mode = 0;
    }
LAB_8017de10:
    *(undefined2*)(state + 0x38) = mode;
    *(u8*)(state + 0x3a) = 4;
    *(float*)&((GroundAnimatorState*)state)->linkedObj = lbl_803DC074;
    ((GroundAnimatorState*)state)->sinkDepth = lbl_803DC074;
    rnd = randomGetRange(0xffff8000, 0x7fff);
    *(short*)(state + 0x48) = (short)rnd;
    rnd = randomGetRange(0xffff8000, 0x7fff);
    *(short*)(state + 0x4a) = (short)rnd;
    *(undefined2*)(state + 0x4c) = 0x2000;
    px = (double)((GameObject*)param_1)->anim.localPosX;
    py = (double)((GameObject*)param_1)->anim.localPosY;
    pz = (double)((GameObject*)param_1)->anim.localPosZ;
    groundResult = FUN_800632d8(px, py, pz, param_1, (float*)(state + 0x30), 0);
    if (groundResult == 0)
    {
        state = *(int*)&((GameObject*)param_1)->extra;
        if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) == 0)
        {
            if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
            {
                ObjHits_DisableObject(param_1);
            }
            *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 2;
        }
        else
        {
            FUN_80017ac8(px, py, pz, in_f4, in_f5, in_f6, in_f7, in_f8, param_1);
        }
    }
    else
    {
        px = (double)*(float*)(state + 0x40);
        py = FUN_80293900(-(double)((float)((double)lbl_803E4470 * px) *
            *(float*)(state + 0x30) - lbl_803E446C));
        pz = (double)(float)((double)lbl_803E4474 * px);
        px = pz;
        if (pz < (double)lbl_803E446C)
        {
            px = -pz;
        }
        if ((double)lbl_803E4478 < px)
        {
            tmp = (double)(float)((double)(float)((double)lbl_803E447C - py) / pz);
            px = (double)(float)((double)(float)((double)lbl_803E447C + py) / pz);
            if ((double)lbl_803E446C < tmp)
            {
                px = tmp;
            }
        }
        else
        {
            px = (double)lbl_803E4460;
        }
        *(float*)(state + 0x50) = (float)px;
        if (lbl_803E446C <= *(float*)(state + 0x28))
        {
            py = (double)lbl_803E4480;
            *(float*)(state + 0x30) =
                (float)(py * (double)(lbl_803E4470 * *(float*)(state + 0x24)) +
                    (double)*(float*)(state + 0x30));
        }
        else
        {
            py = (double)lbl_803E4470;
            *(float*)(state + 0x30) =
                -(float)(py * (double)*(float*)(state + 0x24) - (double)*(float*)(state + 0x30));
        }
        if ((double)lbl_803E446C < (double)*(float*)(state + 0x30))
        {
            *(undefined4*)(state + 0x2c) = *(undefined4*)(param_1 + 0x10);
            *(float*)(state + 0x34) = ((GameObject*)param_1)->anim.localPosY - *(float*)(state + 0x30);
            if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
            {
                ObjHits_DisableObject(param_1);
            }
            FUN_80006824(param_1, SFXen_bridge_stops);
        }
        else
        {
            groundResult = *(int*)&((GameObject*)param_1)->extra;
            if ((*(ushort*)&((GameObject*)param_1)->anim.flags & 0x2000) == 0)
            {
                if (*(int*)&((GameObject*)param_1)->anim.hitReactState != 0)
                {
                    ObjHits_DisableObject(param_1);
                }
                *(byte*)(groundResult + 0x5a) = *(byte*)(groundResult + 0x5a) | 2;
            }
            else
            {
                FUN_80017ac8((double)*(float*)(state + 0x30), py, pz, px, in_f5, in_f6, in_f7, in_f8,
                             param_1);
            }
        }
    }
    return;
}

void FUN_8017de58(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    int player;
    uint bit;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int state;
    double dist;
    undefined8 msgTarget;

    state = *(int*)&((GameObject*)param_9)->extra;
    player = FUN_80017a98();
    dist = (double)FUN_80017710((float*)(player + 0x18), (float*)(param_9 + 0x18));
    if ((dist < (double)lbl_803E4484) &&
        (dist = (double)FUN_8001771c((float*)(player + 0x18), (float*)(param_9 + 0x18)),
            dist < (double)lbl_803E4488))
    {
        bit = GameBit_Get(0x90f);
        if (bit == 0)
        {
            msgTarget = (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
            *(undefined2*)(state + 0x5c) = 0xffff;
            *(undefined2*)(state + 0x5e) = 0;
            *(float*)(state + 0x60) = lbl_803E4460;
            ObjMsg_SendToObject(msgTarget, param_2, param_3, param_4, param_5, param_6, param_7, param_8, player, 0x7000a,
                                param_9, state + 0x5c, in_r7, in_r8, in_r9, in_r10);
            GameBit_Set(0x90f, 1);
            *(byte*)(state + 0x5a) = *(byte*)(state + 0x5a) | 4;
        }
        else
        {
            FUN_80294d60(dist, param_2, param_3, param_4, param_5, param_6, param_7, param_8, player,
                         (uint) * (ushort*)(state + 0x38));
            FUN_80081118((double)lbl_803E4460, param_9, 0xff, 0x28);
            msgTarget = FUN_80006824(param_9, SFXen_waterblock_stop);
            player = *(int*)&((GameObject*)param_9)->extra;
            if ((*(ushort*)&((GameObject*)param_9)->anim.flags & 0x2000) == 0)
            {
                if (*(int*)&((GameObject*)param_9)->anim.hitReactState != 0)
                {
                    ObjHits_DisableObject(param_9);
                }
                *(byte*)(player + 0x5a) = *(byte*)(player + 0x5a) | 2;
            }
            else
            {
                FUN_80017ac8(msgTarget, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            }
        }
    }
    return;
}

/* appleontree_handleCollectableHit: ground-animator collectable hit handler. When player is in
 * range, either send a trigger event (first contact) or apply healing +
 * particle FX + sfx + free-or-disable. */
void appleontree_handleCollectableHit(int obj);

undefined4 FUN_8017e15c(double param_1, undefined2* param_2, int param_3)
{
    float fzero;
    float fa;
    float fb;
    undefined4 result;
    double disc;
    double depth;
    double amp;

    fzero = lbl_803E446C;
    disc = (double)lbl_803E446C;
    depth = (double)*(float*)(param_3 + 0x40);
    if (disc == depth)
    {
        result = 1;
    }
    else
    {
        fa = *(float*)(param_3 + 0x30);
        if (disc <= (double)(fa - (float)((double)*(float*)(param_3 + 0x2c) - param_1)))
        {
            *(float*)(param_2 + 8) = (float)param_1;
            result = 1;
        }
        else
        {
            amp = (double)*(float*)(param_3 + 0x44);
            if (disc == amp)
            {
                disc = FUN_80293900((double)(float)(amp * amp -
                    (double)((float)((double)lbl_803E4470 * depth) * fa
                    )));
                fzero = (float)((double)lbl_803E4474 * depth);
                fa = fzero;
                if (fzero < lbl_803E446C)
                {
                    fa = -fzero;
                }
                fb = lbl_803E4460;
                if (lbl_803E4478 < fa)
                {
                    fa = (float)(-amp - disc) / fzero;
                    fb = (float)(-amp + disc) / fzero;
                    if (lbl_803E446C < fa)
                    {
                        fb = fa;
                    }
                }
                *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fb;
                *(float*)(param_3 + 0x2c) = *(float*)(param_3 + 0x2c) - *(float*)(param_3 + 0x30);
                *(float*)(param_3 + 0x30) = lbl_803E446C;
                *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
                *param_2 = *(undefined2*)(param_3 + 0x48);
                param_2[1] = *(undefined2*)(param_3 + 0x4a);
                param_2[2] = *(undefined2*)(param_3 + 0x4c);
                *(float*)(param_3 + 0x44) = -*(float*)(param_3 + 0x28);
                if ((*(byte*)(param_3 + 0x5a) & 8) == 0)
                {
                    FUN_80006824((uint)param_2, 0x407);
                    *(byte*)(param_3 + 0x5a) = *(byte*)(param_3 + 0x5a) | 8;
                }
                result = 1;
            }
            else if ((double)lbl_803E448C <= amp)
            {
                depth = (double)(float)(depth + (double)*(float*)(param_3 + 0x3c));
                disc = FUN_80293900((double)(float)(amp * amp -
                    (double)((float)((double)lbl_803E4470 * depth) * fa
                    )));
                fzero = (float)((double)lbl_803E4474 * depth);
                fa = fzero;
                if (fzero < lbl_803E446C)
                {
                    fa = -fzero;
                }
                fb = lbl_803E4460;
                if (lbl_803E4478 < fa)
                {
                    fa = (float)(-amp - disc) / fzero;
                    fb = (float)(-amp + disc) / fzero;
                    if (lbl_803E446C < fa)
                    {
                        fb = fa;
                    }
                }
                *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fb;
                *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
                *(float*)(param_3 + 0x44) = *(float*)(param_3 + 0x44) * lbl_803E4490;
                result = 0;
            }
            else
            {
                *(float*)(param_2 + 8) = *(float*)(param_3 + 0x2c);
                *(float*)(param_3 + 0x40) = fzero;
                *(float*)(param_3 + 0x44) = fzero;
                result = 1;
            }
        }
    }
    return result;
}

undefined4 FUN_8017e3c0(double param_1, undefined2* param_2, int param_3)
{
    float fa;
    float fb;
    float fc;
    undefined4 result;
    double disc;
    double depth;
    double amp;

    if (lbl_803E446C == *(float*)(param_3 + 0x3c))
    {
        if (lbl_803E446C <
            *(float*)(param_3 + 0x30) - (float)((double)*(float*)(param_3 + 0x2c) - param_1))
        {
            *(float*)(param_2 + 8) = (float)param_1;
            result = 1;
        }
        else
        {
            depth = (double)*(float*)(param_3 + 0x40);
            amp = (double)*(float*)(param_3 + 0x44);
            disc = FUN_80293900((double)(float)(amp * amp -
                (double)((float)((double)lbl_803E4470 * depth) *
                    *(float*)(param_3 + 0x30))));
            fa = (float)((double)lbl_803E4474 * depth);
            fb = fa;
            if (fa < lbl_803E446C)
            {
                fb = -fa;
            }
            fc = lbl_803E4460;
            if (lbl_803E4478 < fb)
            {
                fb = (float)(-amp - disc) / fa;
                fc = (float)(-amp + disc) / fa;
                if (lbl_803E446C < fb)
                {
                    fc = fb;
                }
            }
            *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fc;
            *(float*)(param_3 + 0x2c) = *(float*)(param_3 + 0x2c) - *(float*)(param_3 + 0x30);
            *(float*)(param_3 + 0x30) = lbl_803E446C;
            *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
            *param_2 = *(undefined2*)(param_3 + 0x48);
            param_2[1] = *(undefined2*)(param_3 + 0x4a);
            param_2[2] = *(undefined2*)(param_3 + 0x4c);
            *(float*)(param_3 + 0x44) =
                lbl_803E4474 * *(float*)(param_3 + 0x40) * fc + *(float*)(param_3 + 0x44);
            *(undefined4*)(param_3 + 0x3c) = *(undefined4*)(param_3 + 0x28);
            (**(code**)(*DAT_803dd718 + 0x10))
            ((double)*(float*)(param_2 + 6), (double)*(float*)(param_3 + 0x34),
             (double)*(float*)(param_2 + 10), param_2);
            result = 0;
        }
    }
    else if ((float)(param_1 - (double)*(float*)(param_3 + 0x2c)) < lbl_803E446C)
    {
        *(float*)(param_2 + 8) = (float)param_1;
        result = 1;
    }
    else
    {
        amp = (double)(*(float*)(param_3 + 0x40) + *(float*)(param_3 + 0x3c));
        depth = (double)*(float*)(param_3 + 0x44);
        disc = FUN_80293900((double)(float)(depth * depth -
            (double)((float)((double)lbl_803E4470 * amp) *
                *(float*)(param_3 + 0x30))));
        fa = (float)((double)lbl_803E4474 * amp);
        fb = fa;
        if (fa < lbl_803E446C)
        {
            fb = -fa;
        }
        fc = lbl_803E4460;
        if (lbl_803E4478 < fb)
        {
            fb = (float)(-depth - disc) / fa;
            fc = (float)(-depth + disc) / fa;
            if (lbl_803E446C < fb)
            {
                fc = fb;
            }
        }
        *(float*)(param_3 + 0xc) = *(float*)(param_3 + 0xc) - fc;
        *(undefined4*)(param_2 + 8) = *(undefined4*)(param_3 + 0x2c);
        *(float*)(param_3 + 0x3c) = lbl_803E4494;
        *(float*)(param_3 + 0x44) = lbl_803E4498;
        result = 0;
    }
    return result;
}

void appleontree_setScale(void);

int appleontree_getExtraSize(void);

u8 appleontree_modelMtxFn(int* obj);

void appleontree_free(int* obj);

void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
