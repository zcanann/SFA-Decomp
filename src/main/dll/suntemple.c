#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/obj_placement.h"
#include "main/objseq.h"
#include "main/objanim_internal.h"

#define SUNTEMPLE_STATE_SIZE 2

#define SUNTEMPLE_RESET_HITBOX_FLAG 0x08
#define SUNTEMPLE_DISABLE_HITBOX_FLAG 0x10
#define SUNTEMPLE_INTERACT_FLAG 0x01

#define SUNTEMPLE_FLAG_HIDE_WHEN_ACTIVE 0x01
#define SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT 0x04
#define SUNTEMPLE_FLAG_CLEAR_GATE_BIT 0x08
#define SUNTEMPLE_FLAG_GATE_REENABLES_HITBOX 0x10
#define SUNTEMPLE_FLAG_PREEMPT_ARG_2 0x20
#define SUNTEMPLE_FLAG_PREEMPT_ARG_3 0x40
#define SUNTEMPLE_FLAG_PREEMPT_ARG_4 0x80

#define SUNTEMPLE_SEQUENCE_INVALID -1
#define SUNTEMPLE_SEQ_WC_INV_USE 0x526
#define SUNTEMPLE_SEQ_TIMER_LOCKOUT 0x830
#define SUNTEMPLE_TEXTURE_LATCHED 0x100
#define SUNTEMPLE_BUTTON_DISABLE_MASK 0x100
#define SUNTEMPLE_GAMEBIT_WC_INV_A 0x25a
#define SUNTEMPLE_GAMEBIT_WC_INV_B 0x25b
#define SUNTEMPLE_GAMEBIT_WC_INV_C 0x202
#define SUNTEMPLE_GAMEBIT_WC_INV_D 0x243

typedef struct SunTempleSetup {
    ObjPlacement base;
    u8 rotXByte;
    u8 rotYByte;
    u8 rotZByte;
    u8 flags;
    s16 activationGameBit;
    s16 readyEventId;
    s8 triggerSlot;
    s8 bankIndex;
    s16 gateGameBit;
    s16 preemptSequenceId;
    s16 pad26;
} SunTempleSetup;

typedef struct SunTempleState {
    u8 activationLatched;
    u8 mapEventMode;
} SunTempleState;

typedef struct SunTempleAnimEvent {
    u8 pad0[0x81];
    u8 commands[10];
    u8 commandCount;
} SunTempleAnimEvent;

STATIC_ASSERT(offsetof(SunTempleSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SunTempleSetup, flags) == 0x1B);
STATIC_ASSERT(offsetof(SunTempleSetup, activationGameBit) == 0x1C);
STATIC_ASSERT(offsetof(SunTempleSetup, readyEventId) == 0x1E);
STATIC_ASSERT(offsetof(SunTempleSetup, triggerSlot) == 0x20);
STATIC_ASSERT(offsetof(SunTempleSetup, bankIndex) == 0x21);
STATIC_ASSERT(offsetof(SunTempleSetup, gateGameBit) == 0x22);
STATIC_ASSERT(offsetof(SunTempleSetup, preemptSequenceId) == 0x24);
STATIC_ASSERT(sizeof(SunTempleSetup) == 0x28);
STATIC_ASSERT(sizeof(SunTempleState) == SUNTEMPLE_STATE_SIZE);
STATIC_ASSERT(offsetof(SunTempleAnimEvent, commands) == 0x81);
STATIC_ASSERT(offsetof(SunTempleAnimEvent, commandCount) == 0x8B);

int suntemple_getExtraSize(void) { return SUNTEMPLE_STATE_SIZE; }

int suntemple_getObjectTypeId(void) { return 0; }

void suntemple_free(void) {}

void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E18);
    }
}

void suntemple_hitDetect(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    if ((objAnim->modelInstance->flags & 1) != 0 && *(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}

int suntemple_interactCallback(int obj, int p2, int p3)
{
    SunTempleSetup *setup = (SunTempleSetup *)((GameObject *)obj)->anim.placementData;
    SunTempleAnimEvent *event = (SunTempleAnimEvent *)p3;
    int i;
    SunVec3 vec = *(SunVec3 *)lbl_802C25D8;

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= SUNTEMPLE_RESET_HITBOX_FLAG;
    for (i = 0; i < event->commandCount; i++) {
        switch (event->commands[i]) {
        default:
            if (setup->flags & SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT) {
                int *tex;
                GameBit_Set(setup->activationGameBit, 1);
                tex = (int *)objFindTexture(obj, 0, 0);
                if (tex != NULL)
                    *tex = SUNTEMPLE_TEXTURE_LATCHED;
            }
            break;
        case 2:
            if (setup->preemptSequenceId != 0)
                (*gObjectTriggerInterface)->yield((u8 *)p3, setup->preemptSequenceId);
            break;
        case 3:
            if (((ObjAnimComponent *)obj)->bankIndex == 1)
                (*gMapEventInterface)->setEventWarpPosition(&vec, -0x4000, getCurMapLayer(), 0);
            break;
        }
    }
    return 0;
}

void suntemple_init(u8 *obj, u8 *setup)
{
    ObjAnimComponent *objAnim;
    SunTempleSetup *setupData;
    SunTempleState *state;

    objAnim = (ObjAnimComponent *)obj;
    setupData = (SunTempleSetup *)setup;
    ((GameObject *)obj)->anim.rotX = (s16)(setupData->rotXByte << 8);
    ((GameObject *)obj)->anim.rotY = (s16)(setupData->rotYByte << 8);
    ((GameObject *)obj)->anim.rotZ = (s16)(setupData->rotZByte << 8);
    ((GameObject *)obj)->animEventCallback = (void *)suntemple_interactCallback;
    objAnim->bankIndex = setupData->bankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    state = ((GameObject *)obj)->extra;
    state->activationLatched = (u8)GameBit_Get(setupData->activationGameBit);
    state->mapEventMode = (*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot);
    if ((setupData->flags & SUNTEMPLE_FLAG_HIDE_WHEN_ACTIVE) != 0 && state->activationLatched != 0) {
        ((GameObject *)obj)->anim.alpha = 0;
    }
    if (state->activationLatched != 0) {
        int *texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = SUNTEMPLE_TEXTURE_LATCHED;
        }
    }
}

void suntemple_update(int obj)
{
    GameObject *gameObj = (GameObject *)obj;
    SunTempleState *state;
    SunTempleSetup *cfg;
    int *texture;
    int flags;

    state = gameObj->extra;
    cfg = (SunTempleSetup *)gameObj->anim.placementData;
    state->activationLatched = (u8)GameBit_Get(cfg->activationGameBit);
    if (state->activationLatched == 0) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
        gameObj->anim.localPosX = cfg->base.posX;
        gameObj->anim.localPosY = cfg->base.posY;
        gameObj->anim.localPosZ = cfg->base.posZ;
        *(u8 *)&gameObj->anim.resetHitboxMode &= ~SUNTEMPLE_RESET_HITBOX_FLAG;

        if (cfg->gateGameBit != -1) {
            if ((u32)GameBit_Get(cfg->gateGameBit) != 0) {
                *(u8 *)&gameObj->anim.resetHitboxMode &= ~SUNTEMPLE_DISABLE_HITBOX_FLAG;
            } else {
                *(u8 *)&gameObj->anim.resetHitboxMode |= SUNTEMPLE_DISABLE_HITBOX_FLAG;
                if ((cfg->flags & SUNTEMPLE_FLAG_GATE_REENABLES_HITBOX) != 0) {
                    *(u8 *)&gameObj->anim.resetHitboxMode |= SUNTEMPLE_RESET_HITBOX_FLAG;
                }
            }
        } else {
            *(u8 *)&gameObj->anim.resetHitboxMode &= ~SUNTEMPLE_DISABLE_HITBOX_FLAG;
        }

        if (gameObj->anim.seqId == SUNTEMPLE_SEQ_TIMER_LOCKOUT && gameTimerIsRunning() != 0) {
            *(u8 *)&gameObj->anim.resetHitboxMode |= SUNTEMPLE_DISABLE_HITBOX_FLAG;
        }

        if ((*(u8 *)&gameObj->anim.resetHitboxMode & SUNTEMPLE_INTERACT_FLAG) != 0) {
            if (cfg->readyEventId == -1 ||
                (*gGameUIInterface)->isEventReady(cfg->readyEventId) != 0) {
                if (cfg->triggerSlot != -1) {
                    if (gameObj->anim.seqId == SUNTEMPLE_SEQ_WC_INV_USE) {
                        if (state->mapEventMode == 1 &&
                            ((u32)GameBit_Get(SUNTEMPLE_GAMEBIT_WC_INV_A) != 0 || (u32)GameBit_Get(SUNTEMPLE_GAMEBIT_WC_INV_B) != 0)) {
                            (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot + 2, (void *)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        } else if (state->mapEventMode == 2 &&
                                   ((u32)GameBit_Get(SUNTEMPLE_GAMEBIT_WC_INV_C) != 0 || (u32)GameBit_Get(SUNTEMPLE_GAMEBIT_WC_INV_D) != 0)) {
                            (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot + 2, (void *)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        } else {
                            (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot, (void *)obj, SUNTEMPLE_SEQUENCE_INVALID);
                        }
                    } else {
                        (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot, (void *)obj, SUNTEMPLE_SEQUENCE_INVALID);
                    }
                }
                if ((cfg->flags & SUNTEMPLE_FLAG_CALLBACK_LATCHES_BIT) == 0) {
                    GameBit_Set(cfg->activationGameBit, 1);
                    texture = objFindTexture(obj, 0, 0);
                    if (texture != NULL) {
                        *texture = SUNTEMPLE_TEXTURE_LATCHED;
                    }
                }
                if ((cfg->flags & SUNTEMPLE_FLAG_CLEAR_GATE_BIT) != 0) {
                    GameBit_Set(cfg->gateGameBit, 0);
                } else {
                    state->activationLatched = 1;
                    gameObj->unkF4 = 1;
                }
                buttonDisable(0, SUNTEMPLE_BUTTON_DISABLE_MASK);
            }
        }
    } else {
        if (gameObj->unkF4 == 0 && cfg->triggerSlot != -1 &&
            cfg->preemptSequenceId != 0) {
            (*gObjectTriggerInterface)->preempt(obj, cfg->preemptSequenceId);
            flags = 1;
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_2) != 0) {
                flags |= 0x2;
            }
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_3) != 0) {
                flags |= 0x3;
            }
            if ((cfg->flags & SUNTEMPLE_FLAG_PREEMPT_ARG_4) != 0) {
                flags |= 0x4;
            }
            (*gObjectTriggerInterface)->runSequence(cfg->triggerSlot, (void *)obj, flags);
        }
        *(u8 *)&gameObj->anim.resetHitboxMode |= SUNTEMPLE_RESET_HITBOX_FLAG;
    }
    gameObj->unkF4 = 1;
}

void suntemple_release(void) {}

void suntemple_initialise(void) {}
