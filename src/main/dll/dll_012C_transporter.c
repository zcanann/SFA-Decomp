/*
 * transporter (DLL 0x12C) - the warp-pad / teleporter object of the CF
 * warp-pad family (WarpPadPlacement / WarpPadState, helpers in
 * CFchuckobj). Each pad is tagged by its placement destinationId (a
 * 32-bit area/event id); the big switches in Transporter_SeqFn and
 * Transporter_init drive per-destination level locking/loading, map
 * warps, env-fx and sky restores, and gate a few pads behind GameBits.
 *
 * Transporter_init seeds state->flags with the pad's warp-fx class from
 * its destinationId (0x68 / 0x08 / 0x30 / 0x10), or sets the
 * gamebit-disabled bit 0x20 when any of a destination's three guard
 * bits is set. Transporter_hitDetect raises/lowers the A-button prompt
 * through the resetHitboxMode interact bits, and Transporter_SeqFn
 * consumes the anim sequence-event opcodes (1 warp, 2 map
 * progress, 3 unlock, 5/6 block flags, 7 pulse fx, 8 env restore).
 *
 * The interact bits live in anim.resetHitboxMode (the signed s8 view of
 * the resetHitboxFlags byte, objanim_internal.h): 0x8 = DISABLED,
 * 0x10 = PROMPT_SUPPRESSED.
 */
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/CF/warp_pad.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objprint_dolphin.h"
#include "main/sfa_shared_decls.h"

/* Env-effect ids activated by Transporter_SeqFn case 8 (env-fx / sky restore
   on arrival), grouped by the destinationId that fires them. Opaque distinct
   roles per index within each destination group. */
#define TRANSPORTER_ENVFX_G0_A 0x224 /* dest 0x43f83 / 0x4977d */
#define TRANSPORTER_ENVFX_G0_B 0x223
#define TRANSPORTER_ENVFX_ENV  0x22e /* shared by G0 and G1 */
#define TRANSPORTER_ENVFX_SKY  0x218 /* shared by G0 and G1 */
#define TRANSPORTER_ENVFX_G1_A 0x217 /* dest 0x48506 / 0x4a533 */
#define TRANSPORTER_ENVFX_G1_B 0x216
#define TRANSPORTER_ENVFX_G1_C 0x84
#define TRANSPORTER_ENVFX_G1_D 0x8a
#define TRANSPORTER_ENVFX_G2_A 0x23a /* dest 0x4b666 / 0x4b667 */
#define TRANSPORTER_ENVFX_G2_B 0x23b
#define TRANSPORTER_ENVFX_G2_C 0x23e
#define TRANSPORTER_ENVFX_G3_A 0x247 /* dest 0x4670d / 0x4827e / 0x49267 */
#define TRANSPORTER_ENVFX_G3_B 0x248
#define TRANSPORTER_ENVFX_G4_A 0x238 /* dest 0x4cb6a */
#define TRANSPORTER_ENVFX_G4_B 0x239

extern f32 lbl_803E3E98;
extern s16 lbl_803DCEB8;

extern void getEnvfxActImmediately(int* a, int* b, int id, int p4);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void objRenderFn_80041018(int obj);

int Transporter_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)obj)->anim.placementData;
    WarpPadState* state = ((GameObject*)obj)->extra;
    int i;
    int id;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 7: /* pulse fx + sfx */
            state->flags = state->flags | WARPPAD_FLAG_PULSE_FX;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_id_420);
            break;
        case 2: /* map progress: lock/load per destination */
            id = setup->destinationId;
            switch (id)
            {
            case 0x49c33:
                mainSetBits(GAMEBIT_SH_WarpStoneRelated0884, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 2, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 3, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 7, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(10, 7, 0);
            case 0x48506:
            case 0x4977d:
                loadMapAndParent(7);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(7), 1);
                break;
            case 0x43f83:
                loadMapAndParent(0x21);
                lockLevel(mapGetDirIdx(0x21), 1);
                break;
            case 0x4a533:
                loadMapAndParent(0x28);
                lockLevel(mapGetDirIdx(0x28), 1);
                break;
            case 0xc5d:
                unlockLevel(mapGetDirIdx(0x21), 1, 0);
                break;
            case 0x47064:
                loadMapAndParent(0x1c);
                lockLevel(mapGetDirIdx(0x1c), 1);
                lockLevel(mapGetDirIdx(0x1b), 0);
                break;
            case 0x4800c:
                loadMapAndParent(0x22);
                lockLevel(mapGetDirIdx(0xd), 0);
                lockLevel(mapGetDirIdx(0x22), 1);
                break;
            case 0x48018:
                unlockLevel(mapGetDirIdx(0x22), 1, 0);
                mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 1);
                mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                break;
            case 0x45dd6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(4), 0);
                break;
            case 0x2ba7:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x12), 0);
                lockLevel(mapGetDirIdx(0x1f), 1);
                loadMapAndParent(0x1f);
                break;
            case 0x46a40:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0xe), 0);
                lockLevel(mapGetDirIdx(0x20), 1);
                loadMapAndParent(0x20);
                break;
            case 0x4b666:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x32), 0);
                lockLevel(mapGetDirIdx(0x15), 1);
                loadMapAndParent(0x15);
                break;
            case 0x497f4:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                lockLevel(mapGetDirIdx(0x27), 1);
                loadMapAndParent(0x27);
                break;
            case 0x4cde6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            }
            break;
        case 3: /* unlock level */
            switch (setup->destinationId)
            {
            case 0x47064:
                unlockLevel(0, 0, 1);
                break;
            }
            break;
        case 5: /* load blocks-set 1 */
            switch (setup->destinationId)
            {
            case 0x47064:
                setLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 6: /* clear blocks-set 1 */
            switch (setup->destinationId)
            {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 1: /* warp out */
            switch (setup->destinationId)
            {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            warpToMap(setup->warpId, 0);
            break;
        case 8: /* env-fx / sky restore on arrival */
            id = setup->destinationId;
            switch (id)
            {
            case 0x43f83:
            case 0x4977d:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G0_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G0_B, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_ENV, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_SKY, 0);
                setDrawCloudsAndLights(0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x48506:
            case 0x4a533:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_B, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_ENV, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_SKY, 0);
                setDrawCloudsAndLights(1);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_C, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_D, 0);
                skyFn_80088c94(1, 0);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x4b666:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_B, 0);
                break;
            case 0x4b667:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_B, 0);
                (*gMapEventInterface)->setObjGroupStatus(0x15, 2, 1);
                getEnvfxActImmediately(0, 0, TRANSPORTER_ENVFX_G2_C, 0);
                skyFn_80088e54(1, lbl_803E3E98);
                break;
            case 0x4670d:
            case 0x4827e:
            case 0x49267:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G3_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G3_B, 0);
                timeOfDayFn_80055000();
                mainSetBits(0xef6, 1);
                break;
            case 0x4cb6a:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G4_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G4_B, 0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
            case 0x4cb84:
                mainSetBits(0xef6, 0);
                break;
            }
            break;
        }
    }
    warpPadFn_8019042c((int)obj);
    return 0;
}

int Transporter_getExtraSize(void)
{
    return 0x10;
}

void Transporter_update(int obj)
{
    register int self = obj;
    register WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)self)->anim.placementData;
    if ((int)setup->warpId != -1)
    {
        warpPadPlayerStandingOn(self);
    }
    warpPadFn_8019042c(self);
}

void Transporter_hitDetect(int obj)
{
    register int self = obj;
    register WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)self)->anim.placementData;
    register WarpPadState* state = ((GameObject*)self)->extra;

    if ((int)lbl_803DCEB8 > -1)
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
            (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode &
                 ~(INTERACT_FLAG_DISABLED | INTERACT_FLAG_PROMPT_SUPPRESSED));
        state->flags = (u8)((u32)state->flags | WARPPAD_FLAG_INTERACTIVE);
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018(self);
        }
        return;
    }

    if ((int)setup->warpId != -1 && (state->flags & WARPPAD_FLAG_DISABLED) == 0)
    {
        if (state->triggerMode != 0 || state->countdownActive != 0)
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
                (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
            state->flags = (u8)((u32)state->flags & ~WARPPAD_FLAG_INTERACTIVE);
        }
        else if ((int)setup->enableGameBit != -1 && mainGetBit((int)setup->enableGameBit) == 0)
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
                (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
                (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED);
            state->flags = (u8)((u32)state->flags & ~WARPPAD_FLAG_INTERACTIVE);
        }
        else
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
                (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode &
                     ~(INTERACT_FLAG_DISABLED | INTERACT_FLAG_PROMPT_SUPPRESSED));
            state->flags = (u8)((u32)state->flags | WARPPAD_FLAG_INTERACTIVE);
        }
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018(self);
        }
        return;
    }

    if ((state->flags & WARPPAD_FLAG_WARP_A) != 0)
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
            (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
    else
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
            (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
            (u8)((u32) * &((GameObject*)self)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED);
    }
    state->flags = (u8)((u32)state->flags & ~WARPPAD_FLAG_INTERACTIVE);
}

void Transporter_render(void)
{
}

void Transporter_init(struct GameObject* obj, u8* params)
{
    WarpPadPlacement* placement;
    WarpPadState* state;
    int id;

    placement = (WarpPadPlacement*)params;
    state = (obj)->extra;
    state->activateDelay = 400;
    state->flags = 0;
    (obj)->anim.rotX = (s16)((u16)(placement->rotXHigh << 8));
    (obj)->unkF4 = 0;
    (obj)->animEventCallback = Transporter_SeqFn;
    *(u8*)&(obj)->anim.resetHitboxMode = (u8)(*(u8*)&(obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);

    id = placement->destinationId;
    switch (id)
    {
    case 0x4670D:
    case 0x4827E:
    case 0x49267:
    case 0x4CB6A:
    case 0x4CB84:
        state->flags = (u8)(state->flags | (WARPPAD_FLAG_WARP_A | WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_WARP_B));
        break;
    case 0x48506:
    case 0x45753:
    case 0x463C0:
    case 0x45DD6:
    case 0x4977D:
    case 0x49C33:
    case 0x4B666:
    case 0x4B667:
        state->flags = (u8)(state->flags | WARPPAD_FLAG_WARP_B);
        break;
    case 0x4C986:
        state->flags = (u8)(state->flags | (WARPPAD_FLAG_DISABLED | WARPPAD_FLAG_WARP_C));
        break;
    case 0x47064:
        state->flags = (u8)(state->flags | WARPPAD_FLAG_WARP_C);
        break;
    case 0x43F83:
        /*
         * NOTE: 0x511 - the last K1 return-pad guard bit - still has no traced
         * setter (set from save/level-event data), left as a raw literal in
         * dll_012C_transporter.c until traced.
         */
        if (mainGetBit(GAMEBIT_K1_SPIRIT_COLLECTED) != 0 || mainGetBit(GAMEBIT_K1_SPIRIT_DEPOSITED) != 0 ||
            mainGetBit(GAMEBIT_TransporterRelated0511) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    case 0x2BA7:
        if (mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit2_Used) != 0 ||
            mainGetBit(GAMEBIT_TransporterRelated029B) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    case 0x46A40:
        if (mainGetBit(GAMEBIT_ITEM_SpiritTestFear_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Unknown8A0_Got) != 0 ||
            mainGetBit(GAMEBIT_ITEM_Unknown8A0_Used) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    case 0x497F4:
        if (mainGetBit(GAMEBIT_ITEM_SpiritTestStrength_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit4_Used) != 0 ||
            mainGetBit(GAMEBIT_TransporterRelated07C1) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    case 0x4800C:
        if (mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit5_Released) != 0 ||
            mainGetBit(0xCB6) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    case 0x4A533:
        if (mainGetBit(GAMEBIT_ITEM_Spirit6_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit6_Released) != 0 ||
            mainGetBit(GAMEBIT_TransportedRelated0CB8) != 0)
        {
            state->flags = (u8)(state->flags | WARPPAD_FLAG_DISABLED);
        }
        break;
    }

    if ((state->flags & WARPPAD_FLAG_WARP_A) != 0)
    {
        *(u8*)&(obj)->anim.resetHitboxMode = (u8)(*(u8*)&(obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
}
