/* DLL 0x0189 — CC SharpClaw pad objects [801AA558-801AA560) */
#include "main/dll/DIM/dimlogfire.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int id);

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

extern int ObjTrigger_IsSet();
extern undefined4 FUN_8008112c();

extern f32 lbl_803E530C;
extern f32 lbl_803E5310;
extern f32 lbl_803E5314;
extern f32 lbl_803E5360;

extern int ObjTrigger_IsSet(int obj);
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern f32 lbl_803E46A8;
extern f32 lbl_803E46AC;
extern f32 lbl_803E46B0;
extern f32 lbl_803E46B4;
extern f32 lbl_803E46B8;
extern f32 lbl_803E46BC;
extern f32 lbl_803E46C0;
extern f32 lbl_803E46C4;
extern u8 fn_801334E0(void);
extern void showHelpText(int textId);
extern int playerIsDisguised(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

void FUN_801aaa6c(double param_1, int param_2, int param_3)
{
    if ((double)lbl_803E530C == param_1)
    {
        *(u8*)(param_2 + 0x10) = 0xc;
        return;
    }
    if ((*(byte*)(param_2 + 0x11) & 2) != 0)
    {
        *(u8*)(param_2 + 0x10) = 1;
        return;
    }
    if ((double)lbl_803E5310 <= param_1)
    {
        *(u8*)(param_2 + 0x10) = 2;
        return;
    }
    if ((*(short*)(param_3 + 0xa0) == 0x18) && (lbl_803E5314 < *(float*)(param_3 + 0x98)))
    {
        *(u8*)(param_2 + 0x10) = 8;
        return;
    }
    if (*(short*)(param_3 + 0xa0) == 0x19)
    {
        *(u8*)(param_2 + 0x10) = 5;
        return;
    }
    *(u8*)(param_2 + 0x10) = 0xb;
    return;
}

undefined4
FUN_801abf38(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    if (animUpdate->eventCount != 0)
    {
        FUN_8008112c((double)lbl_803E5360, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 1, 1, 0, 1, 1, 1, 0);
    }
    return 0;
}

int cclightfoot_getExtraSize(void);
int ccsharpclawpad_getExtraSize(void) { return 0x4; }
int ccpedstal_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void ccsharpclawpad_init(int* obj, int* def)
{
    *(s16*)obj = (s16)((u32) * (u8*)((char*)def + 24) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
}

void cclevcontrol_free(void);

#pragma dont_inline on
#pragma dont_inline reset

/* ccpedstal_updateGameBitGate: state2-driven model + trigger gate. If state2's gamebit at
 * +0x4 is set, latches obj[0xaf] bit 8 and selects model index 1.
 * Otherwise selects model 0, then consults gbit 0xa9: if set, clears the
 * 0x10 flag and (if the obj's trigger 0xa9 is set) fires vtable[0x12],
 * decrements the gamebit, and flags state2[0x6] bit 0. If gbit 0xa9 is
 * clear, sets the obj[0xaf] 0x10 flag instead. */

/* ccpedstal_updateAltVariant: ccpedstal alt-variant think-routine. Toggles obj[0xaf]
 * bit 8 from gbit 0xdc5, then reads state2's gamebit at +0x4: if set,
 * sets bit 8 again and selects model 0; if clear, selects model 1 and
 * (when the obj's pending trigger is asserted) fires vtable[0x12] with
 * id=1, increments gbit 0xa9, and latches state2[0x6] bit 0. Mirrors
 * the no-mark branches into a shared r0=0/cmpwi end-check via goto to
 * match target's layout. */

typedef struct SharpClawPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} SharpClawPadParticleArgs;

void ccsharpclawpad_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    SharpClawPadParticleArgs particleArgs;
    f32* state;
    int* player;

    if (GameBit_Get(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a)) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 2, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        if (GameBit_Get(0x40) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        state = ((GameObject*)obj)->extra;
        if (ObjTrigger_IsSet(obj) != 0 && fn_801334E0() == 0)
        {
            *state = lbl_803E46C0;
        }
        if (*state > lbl_803E46B0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) == 0)
            {
                *state = lbl_803E46B0;
            }
            else
            {
                *state -= timeDelta;
                showHelpText(((GameObject*)obj)->anim.modelInstance->helpTextIds[0]);
            }
        }
        player = (int*)Obj_GetPlayerObject();
        if (vec3f_distanceSquared(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            lbl_803E46C4
            && playerIsDisguised((int)player) != 0)
        {
            Sfx_PlayFromObject(obj, 0x109);
            GameBit_Set(*(s16*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1a), 1);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
        particleArgs.offset[0] = lbl_803E46A8;
        particleArgs.offset[1] = lbl_803E46AC;
        particleArgs.offset[2] = lbl_803E46B0;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
        particleArgs.offset[0] = lbl_803E46AC;
        objfx_spawnArcedBurst(obj, 5, lbl_803E46B4, 5, 2, 0x19, lbl_803E46B8,
                              *(f32*)&lbl_803E46B8, lbl_803E46BC, &particleArgs, 0);
    }
}
