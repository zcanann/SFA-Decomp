/*
 * suntemple (DLL 0x293) - an interactive sun-temple prop driven by the
 * object trigger/sequence system.
 *
 * Each instance carries a SunTempleSetup placement record: rotation
 * bytes, an activation game bit, a "ready" UI event id, a trigger slot,
 * a model bank index, an optional gate game bit, and a preempt sequence
 * id, all gated by the SUNTEMPLE_FLAG_* bits.
 *
 * Until its activation bit latches, suntemple_update watches the
 * engine-written INTERACT_FLAG_ACTIVATED bit in anim.resetHitboxFlags
 * and, when the player interacts, runs the configured trigger
 * sequence - choosing an alternate "+2" slot for the WarpStone-inventory
 * sequence (SUNTEMPLE_SEQ_WC_INV_USE) based on map-event mode and the
 * inventory game bits. Activation either clears a gate bit or latches the
 * activation bit and swaps the texture (SUNTEMPLE_TEXTURE_LATCHED). Once
 * latched it can preempt/run a sequence and is otherwise inert. The
 * SUNTEMPLE_SEQ_TIMER_LOCKOUT sequence disables the hitbox while the game
 * timer is running.
 *
 * suntemple_interactCallback handles the sequence event ids fired during
 * a trigger sequence: latch the activation bit + swap texture (1),
 * yield to a preempt sequence (2), and place a restart point (3).
 *
 * suntemple_hitDetect only runs hit detection while the model instance is
 * visible (modelInstance->flags & 1) - a guard absent from the generic
 * hitDetect helper.
 */
#include "main/dll/dll_0293_suntemple.h"
#include "main/objprint_render_api.h"
#include "main/game_timer.h"
#include "main/game_ui_interface.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/mapEventTypes.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/pad.h"
#include "main/shader_api.h"

/* interact-prompt bits live in anim.resetHitboxFlags (INTERACT_FLAG_*). */

#define SUNTEMPLE_FLAG_HIDE_WHEN_ACTIVE      0x01
#define SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT  0x04
#define SUNTEMPLE_FLAG_CLEAR_GATE_BIT        0x08
#define SUNTEMPLE_FLAG_GATE_REENABLES_HITBOX 0x10
#define SUNTEMPLE_FLAG_PREEMPT_ARG_2         0x20
#define SUNTEMPLE_FLAG_PREEMPT_ARG_3         0x40
#define SUNTEMPLE_FLAG_PREEMPT_ARG_4         0x80

#define SUNTEMPLE_SEQUENCE_INVALID    -1
#define SUNTEMPLE_SEQ_WC_INV_USE      0x526
#define SUNTEMPLE_SEQ_TIMER_LOCKOUT   0x830
#define SUNTEMPLE_TEXTURE_LATCHED     0x100 /* coincidentally equal to SUNTEMPLE_BUTTON_DISABLE_MASK */
#define SUNTEMPLE_BUTTON_DISABLE_MASK 0x100 /* coincidentally equal to SUNTEMPLE_TEXTURE_LATCHED */
#define SUNTEMPLE_GAMEBIT_WC_INV_A    0x25a
#define SUNTEMPLE_GAMEBIT_WC_INV_B    0x25b
#define SUNTEMPLE_GAMEBIT_WC_INV_C    0x202
#define SUNTEMPLE_GAMEBIT_WC_INV_D    0x243

int suntemple_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GameObject* gameObj = obj;
    SunTempleSetup* cfg = (SunTempleSetup*)gameObj->anim.placementData;
    int i;
    Vec3f restartPos = lbl_802C25D8;

    gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
        default:
            if (cfg->flags & SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT)
            {
                ObjTextureRuntimeSlot* tex;
                mainSetBits(cfg->activationGameBit, 1);
                tex = objFindTexture((GameObject*)obj, 0, 0);
                if (tex != NULL)
                    tex->textureId = SUNTEMPLE_TEXTURE_LATCHED;
            }
            break;
        case 2:
            if (cfg->preemptSequenceId != 0)
                (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, cfg->preemptSequenceId);
            break;
        case 3:
            if (gameObj->anim.bankIndex == 1)
                (*gMapEventInterface)->restartPoint(&restartPos, -0x4000, getCurMapLayer(), 0);
            break;
        }
    }
    return 0;
}

int suntemple_getExtraSize(void)
{
    return sizeof(SunTempleState);
}

int suntemple_getObjectTypeId(void)
{
    return 0;
}

void suntemple_free(void)
{
}

void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E18);
    }
}

void suntemple_hitDetect(GameObject* obj)
{
    GameObject* gameObj = obj;
    if ((gameObj->anim.modelInstance->flags & 1) != 0 && gameObj->anim.hitVolumeTransforms != NULL)
    {
        objRenderFn_80041018((GameObject*)obj);
    }
}

void suntemple_update(GameObject* obj)
{
    GameObject* gameObj = obj;
    SunTempleState* state;
    SunTempleSetup* cfg;
    ObjTextureRuntimeSlot* texture;
    int flags;

    state = gameObj->extra;
    cfg = (SunTempleSetup*)gameObj->anim.placementData;
    state->activationLatched = mainGetBit(cfg->activationGameBit);
    if (state->activationLatched == 0)
    {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = 0;
        }
        gameObj->anim.localPosX = cfg->base.posX;
        gameObj->anim.localPosY = cfg->base.posY;
        gameObj->anim.localPosZ = cfg->base.posZ;
        gameObj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;

        if (cfg->gateGameBit != -1)
        {
            if ((u32)mainGetBit(cfg->gateGameBit) != 0)
            {
                gameObj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
            else
            {
                gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                if ((cfg->flags & SUNTEMPLE_FLAG_GATE_REENABLES_HITBOX) != 0)
                {
                    gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
            }
        }
        else
        {
            gameObj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }

        if (gameObj->anim.seqId == SUNTEMPLE_SEQ_TIMER_LOCKOUT && gameTimerIsRunning() != 0)
        {
            gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }

        if ((gameObj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
        {
            if (cfg->readyEventId == -1 || (*gGameUIInterface)->isEventReady(cfg->readyEventId) != 0)
            {
                if (cfg->triggerSlot != -1)
                {
                    if (gameObj->anim.seqId == SUNTEMPLE_SEQ_WC_INV_USE)
                    {
                        if (state->mapEventMode == 1 && ((u32)mainGetBit(SUNTEMPLE_GAMEBIT_WC_INV_A) != 0 ||
                                                         mainGetBit(SUNTEMPLE_GAMEBIT_WC_INV_B) != 0))
                        {
                            (*gObjectTriggerInterface)
                                ->runSequence(cfg->triggerSlot + 2, (void*)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        }
                        else if (state->mapEventMode == 2 && ((u32)mainGetBit(SUNTEMPLE_GAMEBIT_WC_INV_C) != 0 ||
                                                              mainGetBit(SUNTEMPLE_GAMEBIT_WC_INV_D) != 0))
                        {
                            (*gObjectTriggerInterface)
                                ->runSequence(cfg->triggerSlot + 2, (void*)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        }
                        else
                        {
                            (*gObjectTriggerInterface)
                                ->runSequence(cfg->triggerSlot, (void*)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        }
                    }
                    else
                    {
                        (*gObjectTriggerInterface)
                            ->runSequence(cfg->triggerSlot, (void*)obj, SUNTEMPLE_SEQUENCE_INVALID);
                    }
                }
                if ((cfg->flags & SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT) == 0)
                {
                    mainSetBits(cfg->activationGameBit, 1);
                    texture = objFindTexture(obj, 0, 0);
                    if (texture != NULL)
                    {
                        texture->textureId = SUNTEMPLE_TEXTURE_LATCHED;
                    }
                }
                if ((cfg->flags & SUNTEMPLE_FLAG_CLEAR_GATE_BIT) != 0)
                {
                    mainSetBits(cfg->gateGameBit, 0);
                }
                else
                {
                    state->activationLatched = 1;
                    gameObj->unkF4 = 1; /* latches "post-activate"; gates the preempt path below */
                }
                buttonDisable(0, SUNTEMPLE_BUTTON_DISABLE_MASK);
            }
        }
    }
    else
    {
        if (gameObj->unkF4 == 0 && cfg->triggerSlot != -1 && cfg->preemptSequenceId != 0)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, cfg->preemptSequenceId);
            flags = 1;
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_2) != 0)
            {
                flags |= 0x2;
            }
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_3) != 0)
            {
                flags |= 0x3;
            }
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_4) != 0)
            {
                flags |= 0x4;
            }
            (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot, (void*)obj, flags);
        }
        gameObj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
    gameObj->unkF4 = 1;
}

void suntemple_init(GameObject* obj, SunTempleSetup* setup)
{
    GameObject* gameObj = obj;
    SunTempleSetup* cfg = setup;
    SunTempleState* state;

    gameObj->anim.rotX = (s16)(cfg->rotXByte << 8);
    gameObj->anim.rotY = (s16)(cfg->rotYByte << 8);
    gameObj->anim.rotZ = (s16)(cfg->rotZByte << 8);
    gameObj->animEventCallback = suntemple_interactCallback;
    gameObj->anim.bankIndex = cfg->bankIndex;
    if (gameObj->anim.bankIndex >= gameObj->anim.modelInstance->modelCount)
    {
        gameObj->anim.bankIndex = 0;
    }
    state = gameObj->extra;
    state->activationLatched = mainGetBit(cfg->activationGameBit);
    state->mapEventMode = (*gMapEventInterface)->getMapAct(gameObj->anim.mapEventSlot);
    if ((cfg->flags & SUNTEMPLE_FLAG_HIDE_WHEN_ACTIVE) != 0 && state->activationLatched != 0)
    {
        gameObj->anim.alpha = 0;
    }
    if (state->activationLatched != 0)
    {
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            texture->textureId = SUNTEMPLE_TEXTURE_LATCHED;
        }
    }
}

void suntemple_release(void)
{
}

void suntemple_initialise(void)
{
}
