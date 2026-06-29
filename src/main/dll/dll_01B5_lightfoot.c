/*
 * LightFoot Village NPCs (DLL 0x1B5). The village is map "swapcircle"
 * (Cape Claw). The chief who offers the trials is the SC_lightfoo at the
 * throne (placement id 0x45c47), with MuscleFoot (SC_muscleli, 0x460b6)
 * beside him. Chief/MuscleFoot/throne spawn is gated by the village mode
 * (map-event 0xe) via objShouldLoad: their placement map_acts1=0x03 suppresses
 * them in modes 1-2, so they only appear once the village reaches mode >=3
 * (normally 6). Trials: "tracking test" = light all 4 totem poles
 * (sctotempole); "test of strength" = a push-of-war that shoves MuscleFoot
 * into the pit (sctotemstrength). The baby-lightfoot -> blTarget herding gated by
 * 0xc42/0xc46 below is a separate per-NPC reveal, not the chief.
 */
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/player_80295318_shared.h"

typedef struct LightfootState
{
    u8 pad0[0x40C - 0x0];
    s32 unk40C;
} LightfootState;


typedef struct LightfootSub
{
    s32 unk0;
    s32 unk4;
    u8 pad8[0xC - 0x8];
    f32 animTimer;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x24 - 0x18];
    u16 unk24;
    s16 unk26;
    s16 unk28;
    u16 unk2A;
    u8 pad2C[0x30 - 0x2C];
} LightfootSub;


int lightfoot_getExtraSize(void)
{
    return 0x440;
}

int lightfoot_getObjectTypeId(void)
{
    return 0x14b;
}

void lightfoot_hitDetect(void)
{
}

void lightfoot_release(void)
{
}

void lightfoot_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32 scale);
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)p1)->unkF4)
        {
        case 0:
            objRenderFn_8003b8f4(lbl_803E8188);
            break;
        default:
            break;
        }
    }
}

void lightfoot_initialise(void)
{
    lbl_803DB0DC[0] = (int)Lightfoot_UpdateAnimationCycle;
    lbl_803DB0DC[1] = (int)Lightfoot_UpdateButtonTimingChallenge;
    lbl_803DB0DC[2] = (int)Lightfoot_UpdateTargetAnimationCycle;
    lbl_803DB0DC[3] = (int)Lightfoot_UpdateRandomTurn;
    lbl_803DB0DC[4] = (int)Lightfoot_UpdateWanderSteering;
    lbl_803DB0D0[0] = (int)Lightfoot_UpdateChallengeGateInteraction;
    lbl_803DB0D0[1] = (int)Lightfoot_UpdateCompletionInteraction;
    lbl_803DB0D0[2] = (int)Lightfoot_UpdateProximityInteractionState;
}

void lightfoot_free(int obj, int p2)
{
    void* child;
    int inner = *(int*)&((GameObject*)obj)->extra;
    int count;
    int i;
    ObjGroup_RemoveObject(obj, 3);
    count = ((GameObject*)obj)->childCount;
    for (i = 0; i < count; i++)
    {
        child = ((GameObject*)obj)->childObjs[0];
        if (child != NULL)
        {
            ObjLink_DetachChild(obj, child);
            if (p2 == 0)
            {
                Obj_FreeObject((int)child);
            }
        }
    }
    (*(void (*)(int, int, int))(*(int*)(*gBaddieControlInterface + 0x40)))(obj, inner, 0x20);
}

void lightfoot_update(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int p30 = *(int*)&((GameObject*)obj)->anim.placementData;
    int anim = ((LightfootState*)inner)->unk40C;
    f32 snd[3];
    f32 buf[6];
    u8 i;
    f32 limit;
    f32 fv;

    fv = ((LightfootSub*)anim)->unk10;
    if (fv != (limit = lbl_803E8180)) {
        ((LightfootSub*)anim)->unk10 = fv - timeDelta;
        if (((LightfootSub*)anim)->unk10 <= limit) {
            Obj_FreeObject(obj);
        }
    }

    if (((GameObject*)obj)->anim.seqId == 0x27c && ((GroundBaddieState*)inner)->gameBitA != -1)
    {
        switch (((ObjPlacement*)p30)->mapId)
        {
        case 0x4993F:
        case 0x49940:
        case 0x49941:
            if (GameBit_Get(0xc44))
            {
                ((GameObject*)obj)->unkF4 = GameBit_Get(((GroundBaddieState*)inner)->gameBitA);
            }
            else
            {
                ((GameObject*)obj)->unkF4 = 1;
            }
            break;
        case 0x499AC:
        case 0x499AE:
        case 0x499AF:
            if (GameBit_Get(0xc42) && GameBit_Get(((GroundBaddieState*)inner)->gameBitA) == 0)
            {
                void* other = ObjList_FindObjectById(0x499B5);
                if (other != NULL &&
                    Vec_distance((char*)obj + 0x18, (char*)other + 0x18) < lbl_803E8214)
                {
                    GameBit_Set(((GroundBaddieState*)inner)->gameBitA, 1);
                    buf[3] = lbl_803E8180;
                    buf[4] = lbl_803E8218;
                    buf[5] = lbl_803E8180;
                    for (i = 0x14; i != 0; i--)
                    {
                        objfx_spawnDirectionalBurst(obj, 5, lbl_803E81D0, 5, 6, 0x64, lbl_803E8218, buf, 0);
                    }
                    if (GameBit_Get(0xc3b) && GameBit_Get(0xc3c) && GameBit_Get(0xc3d))
                    {
                        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                    }
                    else
                    {
                        Sfx_PlayFromObject(0, 0x409);
                    }
                }
                ((GameObject*)obj)->unkF4 = GameBit_Get(((GroundBaddieState*)inner)->gameBitA);
            }
            else
            {
                ((GameObject*)obj)->unkF4 = 1;
            }
            break;
        case 0x499B0:
        case 0x499B1:
        case 0x499B2:
            if (GameBit_Get(0xc46) && GameBit_Get(((GroundBaddieState*)inner)->gameBitA) == 0)
            {
                void* other = ObjList_FindObjectById(0x499B6);
                if (other != NULL &&
                    Vec_distance((char*)obj + 0x18, (char*)other + 0x18) < lbl_803E8214)
                {
                    GameBit_Set(((GroundBaddieState*)inner)->gameBitA, 1);
                    buf[3] = lbl_803E8180;
                    buf[4] = lbl_803E8218;
                    buf[5] = lbl_803E8180;
                    for (i = 0x14; i != 0; i--)
                    {
                        objfx_spawnDirectionalBurst(obj, 5, lbl_803E81D0, 5, 6, 0x64, lbl_803E8218, buf, 0);
                    }
                    if (GameBit_Get(0xc3e) && GameBit_Get(0xc3f) && GameBit_Get(0xc40))
                    {
                        Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                    }
                    else
                    {
                        Sfx_PlayFromObject(0, 0x409);
                    }
                }
                ((GameObject*)obj)->unkF4 = GameBit_Get(((GroundBaddieState*)inner)->gameBitA);
            }
            else
            {
                ((GameObject*)obj)->unkF4 = 1;
            }
            break;
        default:
            ((GameObject*)obj)->unkF4 = GameBit_Get(((GroundBaddieState*)inner)->gameBitA) == 0;
            break;
        }

        if (((GameObject*)obj)->unkF4 != 0)
        {
            ObjHits_DisableObject(obj);
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
        else
        {
            ObjHits_EnableObject(obj);
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
    }

    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((((ObjPlacement*)p30)->mapId == 0x499B5 && GameBit_Get(0xc42) &&
                (GameBit_Get(0xc3b) == 0 || GameBit_Get(0xc3c) == 0 || GameBit_Get(0xc3d) == 0)) ||
            (((ObjPlacement*)p30)->mapId == 0x499B6 && GameBit_Get(0xc46) &&
                (GameBit_Get(0xc3e) == 0 || GameBit_Get(0xc3f) == 0 || GameBit_Get(0xc40) == 0)))
        {
            buf[3] = lbl_803E8180;
            buf[4] = lbl_803E821C;
            buf[5] = lbl_803E8180;
            objfx_spawnArcedBurst(obj, 5, lbl_803E8220, 1, 6, 0x32, lbl_803E8214, *(f32*)&lbl_803E8214,
                                  lbl_803E8224, buf, 0);
        }
    }
    else
    {
        Lightfoot_UpdateAttachedChild(obj, inner);
        if (((GroundBaddieState*)inner)->flags400 & 0x2)
        {
            Lightfoot_RecordCompletedChallengeTargetHit(obj, inner, anim);
            Lightfoot_ResetScriptedPosition(obj);
            ((GameObject*)obj)->unkF8 = 0;
            ((GroundBaddieState*)inner)->flags400 &= ~0x2;
        }
        Lightfoot_UpdatePlayerInteraction(obj, inner, inner);
        if ((((GroundBaddieState*)inner)->configFlags & 1) && (((GameObject*)obj)->objectFlags & 0x800))
        {
            int a40c = ((LightfootState*)inner)->unk40C;
            ((LightfootSub*)a40c)->animTimer -= timeDelta;
            if (((LightfootSub*)a40c)->animTimer <= lbl_803E8180)
            {
                p30 = 3;
                ((LightfootSub*)a40c)->animTimer += lbl_803E81C0;
            }
            else
            {
                p30 = 0;
            }
            snd[0] = lbl_803E8180;
            snd[1] = lbl_803E81C4;
            snd[2] = lbl_803E8180;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x455);
            ((void (*)(int, f32, int, int, int, void*))fn_80098B18)(obj, lbl_803E81C8 * ((GameObject*)obj)->anim.rootMotionScale, 3, p30, 0, snd);
        }
        ((LightfootSub*)anim)->unk14 -= timeDelta;
    }
}

void lightfoot_init(int obj, int p2, int p3)
{
    u8* base = (u8*)lbl_80334EE8;
    int inner = *(int*)&((GameObject*)obj)->extra;
    ObjPlacement* plc = (ObjPlacement*)p2;
    int sub;
    u8 flags = 0x16;

    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (*)(int, int, int, int, int, int, u8, f32))(*(int*)(*gBaddieControlInterface + 0x58)))(
        obj, p2, inner, 5, 3, 0x108, flags, lbl_803E8228);
    ((GameObject*)obj)->animEventCallback = Lightfoot_SeqFn;
    ((GroundBaddieState*)inner)->baddie.controlMode = 0;
    ((GroundBaddieState*)inner)->baddie.substate = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    sub = ((LightfootState*)inner)->unk40C;
    ((LightfootSub*)sub)->unk26 = -1;
    ((LightfootSub*)sub)->unk28 = ((LightfootSub*)sub)->unk26;
    ((GameObject*)obj)->objectFlags =
        (u16)(((GameObject*)obj)->objectFlags | (*(s8*)((char*)p2 + 0x28) & 0x7));
    if (*(s16*)((char*)p2 + 0x1a) == 0x64c)
    {
        ((GroundBaddieState*)inner)->baddie.controlMode = 2;
        ((GroundBaddieState*)inner)->baddie.substate = 1;
        ObjHits_DisableObject(obj);
        ((LightfootSub*)sub)->unk24 = randomGetRange(0, 3);
        ((LightfootSub*)sub)->unk28 = 0x6f1;
        ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC6F0;
        ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC6F4;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        ((GameObject*)obj)->unkF8 = 0;
    }
    else
    {
        switch (plc->mapId)
        {
        case 0x34316:
            ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC714;
            ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC718;
            ObjHits_DisableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x33e3c:
            ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC6F0;
            ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC6F4;
            ((LightfootSub*)sub)->unk28 = 0x6f1;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x33e34:
            ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC6FC;
            ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC700;
            ((LightfootSub*)sub)->unk28 = 0x6f1;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x45c47:
            ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC708;
            ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC70C;
            ObjHits_DisableObject(obj);
            ((LightfootSub*)sub)->unk28 = 0x6f2;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x460b6:
            ((LightfootSub*)sub)->unk0 = (int)&lbl_803DC720;
            ((LightfootSub*)sub)->unk4 = (int)&lbl_803DC724;
            ObjHits_DisableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x3433f:
            ((LightfootSub*)sub)->unk0 = (int)(base + 0x30);
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x40);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x46a51:
            if (GameBit_Get(0xc52))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            }
            ((LightfootSub*)sub)->unk0 = (int)base;
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x10);
            break;
        case 0x46a55:
            if (GameBit_Get(0xc53))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            }
            ((LightfootSub*)sub)->unk0 = (int)base;
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x10);
            break;
        case 0x49928:
            if (GameBit_Get(0xc54))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            }
            ((LightfootSub*)sub)->unk0 = (int)base;
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x10);
            break;
        case 0x499ac:
        case 0x499ae:
        case 0x499af:
        case 0x499b0:
        case 0x499b1:
        case 0x499b2:
            ((GroundBaddieState*)inner)->baddie.substate = 2;
            ((LightfootSub*)sub)->unk0 = (int)(base + 0x30);
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x40);
            ((LightfootSub*)sub)->unk14 = (f32)(s32)
            randomGetRange(0x78, 0xb4);
            ((GameObject*)obj)->anim.currentMoveProgress = (f32)(s32)
            randomGetRange(0, 0x63) / lbl_803E817C;
            break;
        case 0x499b5:
        case 0x499b6:
            ((GameObject*)obj)->unkF4 = 1;
            ((LightfootSub*)sub)->unk0 = (int)(base + 0x30);
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x40);
            break;
        default:
            ((LightfootSub*)sub)->unk0 = (int)base;
            ((LightfootSub*)sub)->unk4 = (int)(base + 0x10);
            break;
        }
    }
    Lightfoot_ResetScriptedPosition(obj);
    ObjAnim_SetMoveProgress((f32)(s32)randomGetRange(0, 0x63) / lbl_803E817C,
                            (ObjAnimComponent*)obj);
    ((LightfootSub*)sub)->unk2A = (u16)(randomGetRange(0, 1) != 0 ? 0x133 : 0x134);
    ((LightfootSub*)sub)->animTimer = lbl_803E81C0;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ObjHits_DisableObject(obj);
    }
}
