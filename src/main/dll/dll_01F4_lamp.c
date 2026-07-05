/*
 * DLL 0x01F4 - "lamp": a hanging-lamp set-dressing object that swings on a
 * looped path animation and emits particle/sound effects.
 *
 * Lamp_init seeds the lamp's X rotation from its placement def (a different
 * byte per seqId) and installs Lamp_SeqFn as the animation-event callback.
 * Lamp_update advances the swing animation, plays/stops a looped object SFX
 * based on player distance, and (when objectFlags bit LAMP_OBJFLAG_RENDERED is set) spawns
 * trail particles along the object's path each step. Lamp_SeqFn randomly
 * latches the sequence's "A" control flag and spawns a burst of impact
 * particles. Lamp_free stops the SFX channel and releases the exp-gfx source.
 */
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"

#define LAMP_OBJFLAG_RENDERED 0x800

extern s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);
extern void Sfx_StopObjectChannel(int* obj, int channel);

extern f32 Vec_distance(f32* a, f32* b);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

typedef struct LampObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 rotXSwing;           /* 0x18: rotX byte for the non-static swing seq */
    u8 pad19[0x1A - 0x19];
    u8 rotXStatic;          /* 0x1A: rotX byte for the static seq */
    u8 pad1B[0x20 - 0x1B];
} LampObjectDef;

#define LAMP_SEQ_STATIC 0x3e4    /* seqId using the static rotX byte (no swing) */

int Lamp_getExtraSize(void) { return 0x1; }

void Lamp_free(int* obj)
{
    Sfx_StopObjectChannel(obj, 0x40);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Lamp_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, 1.0f);
}

int Lamp_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    u8 effectArgs[0x18];
    PartFxSpawnParams* fx = (PartFxSpawnParams*)effectArgs;
    int i;

    if ((s32)randomGetRange(0, 1) != 0)
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_SET_LATCH_A;
    }
    else
    {
        animUpdate->sequenceControlFlags = OBJSEQ_CONTROL_CLEAR_LATCH_A;
    }
    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair = -1;
    animUpdate->hitVolumePair &= ~0x20;

    if (Obj_GetPlayerObject() == NULL)
    {
        return 0;
    }
    if ((((GameObject*)obj)->objectFlags & LAMP_OBJFLAG_RENDERED) != 0)
    {
        fx->scale = 0.35f;
        fx->arg3 = 0xc0d;
        fx->posX = fx->posX - ((GameObject*)obj)->anim.worldPosX;
        fx->posY = fx->posY - ((GameObject*)obj)->anim.worldPosY;
        fx->posZ = fx->posZ - ((GameObject*)obj)->anim.worldPosZ;
        for (i = 0; i < framesThisStep; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7a8, effectArgs, 6, -1, NULL);
        }
    }
    return 0;
}

void Lamp_update(int obj)
{
    u8 effectArgs[0x18];
    f32 distance;
    int i;

    distance = Vec_distance((void*)((int)Obj_GetPlayerObject() + 0x18), (void*)(obj + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) == 0)
    {
        if (distance < 100.0f)
        {
            Sfx_PlayFromObject((int*)obj, SFXmn_eggylaugh216);
        }
    }
    else if (distance >= 100.0f)
    {
        Sfx_StopObjectChannel((int*)obj, 0x40);
    }

    if (((GameObject*)obj)->anim.seqId != LAMP_SEQ_STATIC)
    {
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->unkF8 = 1;
            ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 90) / 100.0f,
                                    (ObjAnimComponent*)obj);
        }
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, 0.003f,
                                                                     timeDelta, NULL);
    }

    if ((((GameObject*)obj)->objectFlags & LAMP_OBJFLAG_RENDERED) != 0)
    {
        *(f32*)(effectArgs + 8) = 0.35f;
        *(s16*)(effectArgs + 6) = 0xc0d;
        *(f32*)(effectArgs + 0xc) = 0.0f;
        *(f32*)(effectArgs + 0x10) = -12.0f;
        *(f32*)(effectArgs + 0x14) = 0.0f;
        ObjPath_GetPointWorldPosition(obj, 0, (f32*)(effectArgs + 0xc), (f32*)(effectArgs + 0x10),
                                      (f32*)(effectArgs + 0x14), 1);
        if (((GameObject*)obj)->anim.parent != NULL)
        {
            *(f32*)(effectArgs + 0xc) = *(f32*)(effectArgs + 0xc) - ((GameObject*)obj)->anim.worldPosX;
            *(f32*)(effectArgs + 0x10) = *(f32*)(effectArgs + 0x10) - ((GameObject*)obj)->anim.worldPosY;
            *(f32*)(effectArgs + 0x14) = *(f32*)(effectArgs + 0x14) - ((GameObject*)obj)->anim.worldPosZ;
        }
        else
        {
            *(f32*)(effectArgs + 0xc) = *(f32*)(effectArgs + 0xc) - ((GameObject*)obj)->anim.localPosX;
            *(f32*)(effectArgs + 0x10) = *(f32*)(effectArgs + 0x10) - ((GameObject*)obj)->anim.localPosY;
            *(f32*)(effectArgs + 0x14) = *(f32*)(effectArgs + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        }
        for (i = 0; i < framesThisStep; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7c7, effectArgs, 2, -1, NULL);
        }
    }
}

void Lamp_init(int* obj, int* def)
{
    s8* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == LAMP_SEQ_STATIC)
    {
        ((GameObject*)obj)->anim.rotX = (s16)((u32)((LampObjectDef*)def)->rotXStatic << 8);
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (s16)((s32)((LampObjectDef*)def)->rotXSwing << 8);
    }
    ((GameObject*)obj)->anim.rotY = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->unkF8 = 0;
    *state = 1;
    ((GameObject*)obj)->animEventCallback = Lamp_SeqFn;
}
