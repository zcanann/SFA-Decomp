#include "main/dll/CF/CFchuckobj.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/CF/warp_pad.h"
#include "main/objseq.h"

typedef struct WarpPadPlayerStandingOnPlacement
{
    u8 pad0[0x20 - 0x0];
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WarpPadPlayerStandingOnPlacement;

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int ObjTrigger_IsSet();
extern f32 Vec_xzDistance(f32 * posA, f32 * posB);
extern f32 vec3f_distanceSquared(f32 * posA, f32 * posB);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);
extern int Obj_GetPlayerObject(void);
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern u8 lbl_803DCDE0;
extern s16 lbl_803DCEB8;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f64 DOUBLE_803e4af8;
extern f32 FLOAT_803e4b00;
extern f32 lbl_803E3E98;
extern f32 lbl_803E3E9C;
extern f32 lbl_803E3EA0;
extern f32 lbl_803E3EA4;
extern f32 lbl_803E3EA8;
extern f32 lbl_803E3EAC;
extern f32 lbl_803E3EB0;
extern f32 lbl_803E3EB4;
extern f32 lbl_803E3EB8;
extern f32 lbl_803E3EBC;
extern f32 lbl_803E3EC0;
extern f32 lbl_803E3EC4;
extern f32 lbl_803E3EC8;
extern f32 lbl_803E3ECC;
extern f32 lbl_803E3ED0;
extern f32 lbl_803E3EE0;

extern void setAButtonIcon(int iconId);

#pragma scheduling on
#pragma peephole on

void FUN_8018f650(void)
{
    byte mode;
    int obj;
    int* emitter;
    short i;
    int data;
    double in_f31;
    double bias;
    double in_ps31_1;
    ushort local_68;
    undefined2 local_66;
    short local_64;
    u8 auStack_60[8];
    float local_58;
    float local_54;
    float local_50;
    float local_4c;
    undefined4 local_48;
    uint uStack_44;
    undefined4 local_40;
    uint uStack_3c;
    undefined4 local_38;
    uint uStack_34;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    obj = FUN_8028683c();
    data = *(int *)&((GameObject *)obj)->extra;
    local_58 = FLOAT_803e4b00;
    mode = *(byte*)(data + 8);
    if (mode == 0)
    {
        if (*(short*)(data + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            local_68 = *(ushort*)(data + 0x1a);
            local_66 = *(undefined2*)(data + 0x1c);
            local_64 = *(short*)(data + 0x1e);
            if (*(int *)&((GameObject *)obj)->anim.parent != 0)
            {
                local_64 = local_64 + *(short*)(*(int *)&((GameObject *)obj)->anim.parent + 4);
            }
            FUN_80017748(&local_68, &local_54);
            local_54 = local_54 + ((GameObject*)obj)->anim.localPosX;
            local_50 = local_50 + ((GameObject*)obj)->anim.localPosY;
            local_4c = local_4c + ((GameObject*)obj)->anim.localPosZ;
            (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                             auStack_60, 0x200001, -1, NULL);
        }
        else
        {
            bias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(data + 0xc); i = i + 1)
            {
                uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_44) - bias);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - bias);
                uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_34) - bias);
                local_68 = *(ushort*)(data + 0x1a);
                local_66 = *(undefined2*)(data + 0x1c);
                local_64 = *(short*)(data + 0x1e);
                if (*(int *)&((GameObject *)obj)->anim.parent != 0)
                {
                    local_64 = local_64 + *(short*)(*(int *)&((GameObject *)obj)->anim.parent + 4);
                }
                FUN_80017748(&local_68, &local_54);
                local_54 = local_54 + ((GameObject*)obj)->anim.localPosX;
                local_50 = local_50 + ((GameObject*)obj)->anim.localPosY;
                local_4c = local_4c + ((GameObject*)obj)->anim.localPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                 auStack_60, 0x200001, -1, NULL);
            }
        }
    }
    else if (mode == 1)
    {
        emitter = (int*)FUN_80006b14(*(ushort*)(data + 10) + 0x58 & 0xffff);
        if (*(short*)(data + 0xc) < 1)
        {
            (**(code**)(*emitter + 4))(obj, 0, 0, 1, 0xffffffff, 0);
        }
        else
        {
            for (i = 0; i < *(short*)(data + 0xc); i = i + 1)
            {
                (**(code**)(*emitter + 4))(obj, 0, 0, 1, 0xffffffff, 0);
            }
        }
        FUN_80006b0c((undefined*)emitter);
    }
    else if (mode == 2)
    {
        emitter = (int*)FUN_80006b14(*(ushort*)(data + 10) + 0xab & 0xffff);
        if (*(short*)(data + 0xc) < 1)
        {
            (**(code**)(*emitter + 4))(obj, 0, 0, 1, 0xffffffff, *(ushort*)(data + 10) & 0xff, 0);
        }
        else
        {
            for (i = 0; i < *(short*)(data + 0xc); i = i + 1)
            {
                (**(code**)(*emitter + 4))(obj, 0, 0, 1, 0xffffffff, *(ushort*)(data + 10) & 0xff, 0);
            }
        }
        FUN_80006b0c((undefined*)emitter);
    }
    else if (mode == 3)
    {
        if (*(short*)(data + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            local_68 = *(ushort*)(data + 0x1a);
            local_66 = *(undefined2*)(data + 0x1c);
            local_64 = *(short*)(data + 0x1e);
            if (*(int *)&((GameObject *)obj)->anim.parent != 0)
            {
                local_64 = local_64 + *(short*)(*(int *)&((GameObject *)obj)->anim.parent + 4);
            }
            FUN_80017748(&local_68, &local_54);
            (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                             auStack_60, 2, -1, NULL);
        }
        else
        {
            bias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(data + 0xc); i = i + 1)
            {
                uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_34) - bias);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - bias);
                uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_44) - bias);
                local_68 = *(ushort*)(data + 0x1a);
                local_66 = *(undefined2*)(data + 0x1c);
                local_64 = *(short*)(data + 0x1e);
                if (*(int *)&((GameObject *)obj)->anim.parent != 0)
                {
                    local_64 = local_64 + *(short*)(*(int *)&((GameObject *)obj)->anim.parent + 4);
                }
                FUN_80017748(&local_68, &local_54);
                (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                 auStack_60, 2, -1, NULL);
            }
        }
    }
    else if (5 < mode)
    {
        if (*(short*)(data + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            FUN_80017748((ushort*)(data + 0x1a), &local_54);
            if (*(char*)(data + 8) == '\x06')
            {
                local_54 = local_54 + ((GameObject*)obj)->anim.localPosX;
                local_50 = local_50 + ((GameObject*)obj)->anim.localPosY;
                local_4c = local_4c + ((GameObject*)obj)->anim.localPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                 auStack_60, 0x200001, -1, NULL);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                 auStack_60, 2, -1, NULL);
            }
        }
        else
        {
            bias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(data + 0xc); i = i + 1)
            {
                uStack_34 = randomGetRange(-(uint) * (ushort*)(data + 0x14), (uint) * (ushort*)(data + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_34) - bias);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(data + 0x18), (uint) * (ushort*)(data + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - bias);
                uStack_44 = randomGetRange(-(uint) * (ushort*)(data + 0x16), (uint) * (ushort*)(data + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_44) - bias);
                FUN_80017748((ushort*)(data + 0x1a), &local_54);
                if (*(char*)(data + 8) == '\x06')
                {
                    local_54 = local_54 + ((GameObject*)obj)->anim.localPosX;
                    local_50 = local_50 + ((GameObject*)obj)->anim.localPosY;
                    local_4c = local_4c + ((GameObject*)obj)->anim.localPosZ;
                    (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                     auStack_60, 0x200001, -1, NULL);
                }
                else
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, *(undefined2*)(data + 10),
                                                     auStack_60, 2, -1, NULL);
                }
            }
        }
    }
    FUN_80286888();
    return;
}

#pragma scheduling off
#pragma peephole off
void warpPadFn_8019042c(int obj)
{
    WarpPadState* state;
    int player;
    u8 flags;
    u8 i;
    struct
    {
        s16 unk0;
        s16 mode;
        s16 effectId;
        s16 count;
        f32 scale;
        f32 pos[3];
    } fx;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    fx.pos[0] = lbl_803E3E98;
    fx.pos[1] = lbl_803E3E9C;
    fx.pos[2] = lbl_803E3E98;
    flags = state->flags;

    if ((flags & 0x40) != 0)
    {
        if ((flags & 8) != 0)
        {
            fx.effectId = 0xc0e;
            fx.mode = 1;
        }
        else if ((flags & 0x10) != 0)
        {
            fx.effectId = 0xc7e;
            fx.mode = 2;
        }
        else
        {
            fx.effectId = 0xc13;
            fx.mode = 0;
        }
    }
    else if ((flags & 8) != 0)
    {
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E3EA0)
        {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 1, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc0e;
        fx.mode = 1;
    }
    else if ((flags & 0x10) != 0)
    {
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E3EA0)
        {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 5, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc7e;
        fx.mode = 2;
    }
    else
    {
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E3EA0)
        {
            if (((state->flags & 0xa0) != 0) && (state->countdownActive == 0))
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EA4, 2, 7, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
            else
            {
                objfx_spawnArcedBurst(obj, 1, lbl_803E3EB0, 3, 6, 100,
                                      lbl_803E3EA8, *(f32*)&lbl_803E3EA8, lbl_803E3EAC, &fx, 0);
            }
        }
        fx.effectId = 0xc13;
        fx.mode = 0;
    }

    if ((state->flags & 4) != 0)
    {
        if (state->pulseTimer < lbl_803E3EB4)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
        }
        else if (state->pulseTimer < lbl_803E3EB8)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer / lbl_803E3EBC
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
            fx.count = 0x28;
            fx.unk0 = 0;
            fx.scale = lbl_803E3EC0 * ((state->pulseTimer - lbl_803E3EB4) / lbl_803E3EC4);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7d2, &fx, 2, -1, NULL);
            state->flags = state->flags | 2;
        }
        else if (state->pulseTimer < lbl_803E3EC8)
        {
            if ((f32)(s32)randomGetRange(0, 0x1e0) < state->pulseTimer * lbl_803E3EB0
            )
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ca, &fx, 2, -1, NULL);
            }
            if ((state->flags & 2) != 0)
            {
                state->flags = state->flags & ~2;
                fx.count = 0x46;
                fx.scale = lbl_803E3ECC;
                for (i = 0xf; i != 0; i--)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7d2, &fx, 2, -1, NULL);
                }
            }
        }
        else if (!(state->pulseTimer < lbl_803E3ED0))
        {
            state->pulseTimer = lbl_803E3E98;
            state->flags = state->flags & ~4;
        }
        state->pulseTimer = state->pulseTimer + timeDelta;
    }
}

void warpPadPlayerStandingOn(int obj)
{
    int def;
    WarpPadState* state;
    int player;
    s16 gameBit;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    gameBit = *(s16*)(def + 0x20);
    if (gameBit != -1)
    {
        if (GameBit_Get(gameBit) != 0)
        {
            state->flags = state->flags & ~0x80;
        }
        else
        {
            state->flags = state->flags | 0x80;
        }
    }

    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
    {
        setAButtonIcon(0x1b);
        if (GameBit_Get(0x912) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            GameBit_Set(0x912, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if ((void*)player == NULL)
    {
        return;
    }

    if ((state->triggerMode == 0) && (state->countdownActive == 0) &&
        ((((GameObject*)obj)->objectFlags & 0x1000) == 0))
    {
        if (lbl_803DCEB8 > -1)
        {
            player = Obj_GetPlayerObject();
            if (Vec_xzDistance((f32*)(obj + 0x18), (f32*)(player + 0x18)) < lbl_803E3EE0)
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                ((GameObject*)obj)->unkF4 = state->activateDelay;
                state->triggerMode = 0;
                state->countdownActive = 1;
                lbl_803DCDE0 = 2;
                goto updateTimer;
            }
        }
        gameBit = ((WarpPadPlayerStandingOnPlacement*)def)->unk20;
        if (((gameBit == -1) ||
                ((GameBit_Get(gameBit) != 0) && ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0))) &&
            (ObjTrigger_IsSet(obj) != 0))
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            ((GameObject*)obj)->unkF4 = state->activateDelay;
            state->triggerMode = 1;
            state->countdownActive = 1;
        }
    }

updateTimer:
    if (state->countdownActive != 0)
    {
        if (((GameObject*)obj)->unkF4 > 0)
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        }
        else
        {
            ((GameObject*)obj)->unkF4 = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer = state->cooldownTimer - timeDelta;
    if (state->cooldownTimer <= *(f32*)&lbl_803E3E98)
    {
        state->cooldownTimer = lbl_803E3E98;
        state->unk0A = -1;
    }
}

void areafxemit_free(AreaFxEmitObject* obj);
