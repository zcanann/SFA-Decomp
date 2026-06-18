/* DLL 0x0110 — door objects [8017AC2C-8017ADB4) */

#include "main/dll/cfguardian_state.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/alphaanim.h"
#include "main/objtexture.h"

typedef struct DoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 unk1C;
    u8 unk1D;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} DoorObjectDef;

typedef struct DoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DoorPlacement;

extern u32 ObjHits_DisableObject();

extern u32 GameBit_Get(int eventId);
extern int Sfx_PlayFromObject(int obj, int sfxId);

__declspec(section ".sdata") extern char lbl_803DBD90[];

extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern uint GameBit_Get(int eventId);

int Door_getExtraSize(void) { return 0x8; }
int mmp_bridge_getExtraSize(void);

void Door_render(void) { objRenderFn_8003b8f4(lbl_803E3780); }

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

void Door_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    state[5] = 1;
    ((GameObject*)obj)->anim.rotX = (s16)(def[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)Door_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)((DoorObjectDef*)def)->unk21 * lbl_803E3784;
    if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3788)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3780;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (((DoorObjectDef*)def)->unk1A != -1)
    {
        state[4] = (u8)GameBit_Get(((DoorObjectDef*)def)->unk1A);
    }
    else
    {
        state[4] = 0;
    }
    state[6] = 0;
    if (GameBit_Get(((DoorObjectDef*)def)->unk18) != 0) state[6] = (u8)(state[6] | 1);
    if (GameBit_Get(((DoorObjectDef*)def)->unk22) != 0) state[6] = (u8)(state[6] | 2);
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        switch (model)
        {
        case 1101:
            {
                s32 subtype = ((GameObject*)obj)->anim.mapEventSlot;
                if ((subtype >= 40 && subtype < 43) || (subtype < 35 && subtype >= 31))
                {
                    *(s16*)state = 832;
                    *(s16*)&((CfGuardianState*)state)->sfxId = 833;
                }
                else
                {
                    *(s16*)state = 1154;
                    *(s16*)&((CfGuardianState*)state)->sfxId = 1155;
                }
                break;
            }
        case 358:
            *(s16*)state = 275;
            *(s16*)&((CfGuardianState*)state)->sfxId = 504;
            break;
        }
    }
}

void Door_update(int obj)
{
    int state;
    int def;
    int triggerArg;
    int triggerId;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (*(u8*)(state + 5) != 0)
    {
        triggerId = ((DoorPlacement*)def)->unk1C;
        if ((triggerId != 0) && (*(u8*)(state + 4) != 0))
        {
            triggerArg = *(u8*)(def + 0x20) & 0x7f;
            (*gObjectTriggerInterface)->preempt(obj, triggerId);
        }
        else
        {
            triggerArg = -1;
        }
        if (*(s8*)&((DoorPlacement*)def)->unk1E != -1)
        {
            (*gObjectTriggerInterface)->runSequence((int)*(s8*)&((DoorPlacement*)def)->unk1E, (void*)obj, triggerArg);
        }
        *(u8*)(state + 5) = 0;
    }
}

void mmp_bridge_update(int* obj);

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int GameBit_Set(int eventId, int value); /* #57 */
    int i;
    int state;
    int def;
    int opened;
    int closeReady;
    ObjTextureRuntimeSlot* tex;
    int ret;

    state = *(int*)&((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        ObjHits_DisableObject(obj);
    }
    if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
    {
        if ((*(u8*)(state + 6) & 1) != 0)
        {
            tex = objFindTexture((int*)obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
        if ((*(u8*)(state + 6) & 2) != 0)
        {
            tex = objFindTexture((int*)obj, 1, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
    }
    if (*(u8*)(state + 4) == 0)
    {
        opened = GameBit_Get(((DoorPlacement*)def)->unk18);
        closeReady = 0;
        if ((((DoorPlacement*)def)->unk22 == -1) || (GameBit_Get(((DoorPlacement*)def)->unk22) != 0))
        {
            closeReady = 1;
        }
        if ((opened != 0) && ((*(u8*)(state + 6) & 1) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, 0x4b);
            }
            *(u8*)(state + 6) |= 1;
        }
        if ((closeReady != 0) && ((*(u8*)(state + 6) & 2) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, 0x4b);
            }
            *(u8*)(state + 6) |= 2;
        }
        if (*(u8*)(state + 6) == 3)
        {
            *(u8*)(state + 4) = 2;
            if (*(u16*)state != 0)
            {
                Sfx_PlayFromObject(obj, *(u16*)state);
            }
        }
    }
    else if (*(u8*)(state + 4) == 1)
    {
        if (GameBit_Get(((DoorPlacement*)def)->unk18) == 0)
        {
            *(u8*)(state + 4) = 3;
            if (*(u16*)state != 0)
            {
                Sfx_PlayFromObject(obj, *(u16*)state);
            }
        }
    }
    if (*(u8*)(state + 4) == 2)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 2)
            {
                *(u8*)(state + 4) = 1;
                if (((DoorPlacement*)def)->unk1A != -1)
                {
                    GameBit_Set(((DoorPlacement*)def)->unk1A, 1);
                }
                if ((*(u16*)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16*)state) != 0))
                {
                    Sfx_StopFromObject(obj, *(u16*)state);
                }
                if (((CfGuardianState*)state)->sfxId != 0)
                {
                    Sfx_PlayFromObject(obj, ((CfGuardianState*)state)->sfxId);
                }
            }
        }
    }
    else if (*(u8*)(state + 4) == 3)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 1)
            {
                *(u8*)(state + 4) = 0;
                *(u8*)(state + 6) = 0;
                if (((DoorPlacement*)def)->unk1A != -1)
                {
                    GameBit_Set(((DoorPlacement*)def)->unk1A, 0);
                }
                if ((*(u16*)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16*)state) != 0))
                {
                    Sfx_StopFromObject(obj, *(u16*)state);
                }
                if (((CfGuardianState*)state)->sfxId != 0)
                {
                    Sfx_PlayFromObject(obj, ((CfGuardianState*)state)->sfxId);
                }
            }
        }
    }
    ret = 0;
    if ((*(u8*)(state + 4) != 2) && (*(u8*)(state + 4) != 3))
    {
        ret = 1;
    }
    return ret;
}

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
