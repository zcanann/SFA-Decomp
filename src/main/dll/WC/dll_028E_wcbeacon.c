#include "main/dll/dll_80220608_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

#define WCBEACON_EXTRA_SIZE 0x8

#define WCBEACON_RENDER_TYPE_BASE 0x400
#define WCBEACON_RENDER_TYPE_SHIFT 0xb

#define WCBEACON_SETUP_TYPE_OFFSET 0x18
#define WCBEACON_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCBEACON_SETUP_SOLVED_BIT_OFFSET 0x1e
#define WCBEACON_SETUP_ARM_BIT_OFFSET 0x20

#define WCBEACON_STATE_TIMER 0x0
#define WCBEACON_STATE_PHASE 0x4
#define WCBEACON_STATE_ACCEPTED_INTERACTION 0x5

#define WCBEACON_PHASE_IDLE 0
#define WCBEACON_PHASE_WAITING_FOR_TRICKY 1
#define WCBEACON_PHASE_ACTIVATING 2
#define WCBEACON_PHASE_ACTIVE 3

#define WCBEACON_BLOCK_PLAYER_FLAG 0x8
#define WCBEACON_TRICKY_PROMPT_FLAG 0x4
#define WCBEACON_VISIBLE_PARTFX_FLAG 0x800

#define WCBEACON_PARTFX_ACTIVE 0x73a
#define WCBEACON_PARTFX_KIND 2
#define WCBEACON_TRIGGER_ARM_SLOT 0
#define WCBEACON_TRIGGER_RELEASE_SLOT 1
#define WCBEACON_TRIGGER_ACCEPT_ARG 1
#define WCBEACON_TRIGGER_NO_ARG -1
#define WCBEACON_FINAL_TRIGGER_ID 105

#define WCBEACON_STATE_TIMER_VALUE(state) (*(f32 *)((state) + WCBEACON_STATE_TIMER))
#define WCBEACON_STATE_PHASE_VALUE(state) (*(u8 *)((state) + WCBEACON_STATE_PHASE))
#define WCBEACON_STATE_ACCEPTED_INTERACTION_VALUE(state) \
    (*(u8 *)((state) + WCBEACON_STATE_ACCEPTED_INTERACTION))


#pragma peephole on
#pragma scheduling off
int wcbeacon_aButtonCallback(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;

    if (isGameTimerDisabled() == 0) {
        WCBEACON_STATE_ACCEPTED_INTERACTION_VALUE(state) = 1;
        GameBit_Set(*(s16 *)(setup + WCBEACON_SETUP_SOLVED_BIT_OFFSET), 1);
    }
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcbeacon_getExtraSize(void) { return WCBEACON_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcbeacon_getObjectTypeId(int obj)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    int modelIndex = *(s8 *)(*(int *)&((GameObject *)obj)->anim.placementData + WCBEACON_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCBEACON_RENDER_TYPE_SHIFT) | WCBEACON_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DE0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbeacon_update(int obj)
{
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    int state = *(int *)&((GameObject *)obj)->extra;
    u32 phase;

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= WCBEACON_BLOCK_PLAYER_FLAG;
    phase = WCBEACON_STATE_PHASE_VALUE(state);
    if (phase == WCBEACON_PHASE_WAITING_FOR_TRICKY) {
        int tricky = getTrickyObject();
        if ((u32)GameBit_Get(*(s16 *)(setup + WCBEACON_SETUP_ARM_BIT_OFFSET)) == 0) {
            if ((u32)fn_80138F84(tricky) != (u32)obj || trickyFn_80138f14(tricky) != 0) {
                ((ObjectTriggerInterface *)*gObjectTriggerInterface)
                    ->runSequence(WCBEACON_TRIGGER_RELEASE_SLOT, (void *)obj, WCBEACON_TRIGGER_NO_ARG);
                WCBEACON_STATE_PHASE_VALUE(state) = WCBEACON_PHASE_IDLE;
            }
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~WCBEACON_BLOCK_PLAYER_FLAG;
            if ((u32)tricky != 0 && (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & WCBEACON_TRICKY_PROMPT_FLAG)) {
                (*(void (**)(int, int, int, int, int))(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(
                    tricky, obj, WCBEACON_TRIGGER_ACCEPT_ARG, WCBEACON_TRICKY_PROMPT_FLAG,
                    *(int *)(*(int *)(tricky + 0x68)));
            }
        }
        if (WCBEACON_STATE_ACCEPTED_INTERACTION_VALUE(state) != 0) {
            Sfx_PlayFromObject(obj, SFXmv_mushdizzylp12);
            Sfx_PlayFromObject(obj, SFXmv_liftloop);
            WCBEACON_STATE_PHASE_VALUE(state) = WCBEACON_PHASE_ACTIVATING;
            WCBEACON_STATE_TIMER_VALUE(state) = lbl_803E6DE4;
        }
    } else if (phase == WCBEACON_PHASE_IDLE) {
        if ((u32)GameBit_Get(*(s16 *)(setup + WCBEACON_SETUP_ARM_BIT_OFFSET)) != 0) {
            ((ObjectTriggerInterface *)*gObjectTriggerInterface)
                ->runSequence(WCBEACON_TRIGGER_ARM_SLOT, (void *)obj, WCBEACON_TRIGGER_NO_ARG);
            WCBEACON_STATE_PHASE_VALUE(state) = WCBEACON_PHASE_WAITING_FOR_TRICKY;
        }
    } else if (phase == WCBEACON_PHASE_ACTIVATING) {
        f32 v = WCBEACON_STATE_TIMER_VALUE(state) + timeDelta;
        WCBEACON_STATE_TIMER_VALUE(state) = v;
        if (v >= lbl_803E6DE8) {
            WCBEACON_STATE_PHASE_VALUE(state) = WCBEACON_PHASE_ACTIVE;
        }
    } else if (phase == WCBEACON_PHASE_ACTIVE) {
        if (((GameObject *)obj)->objectFlags & WCBEACON_VISIBLE_PARTFX_FLAG) {
            (*gPartfxInterface)->spawnObject((void *)obj, WCBEACON_PARTFX_ACTIVE, NULL,
                                             WCBEACON_PARTFX_KIND, WCBEACON_TRIGGER_NO_ARG, NULL);
        }
        if (((GameObject *)obj)->unkF4 == 0) {
            (*gObjectTriggerInterface)->preempt(obj, WCBEACON_FINAL_TRIGGER_ID);
            ((ObjectTriggerInterface *)*gObjectTriggerInterface)
                ->runSequence(WCBEACON_TRIGGER_ARM_SLOT, (void *)obj, WCBEACON_TRIGGER_ACCEPT_ARG);
        }
    }
    ((GameObject *)obj)->unkF4 = 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbeacon_init(u8 *obj, u8 *setup)
{
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
    u8 *state = ((GameObject *)obj)->extra;
    s16 objType;

    ((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac));
    objType = (s16)((s8)setup[WCBEACON_SETUP_TYPE_OFFSET] << 8);
    *(s16 *)obj = objType;
    objAnim->bankIndex = setup[WCBEACON_SETUP_MODEL_INDEX_OFFSET];
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + WCBEACON_SETUP_ARM_BIT_OFFSET)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + WCBEACON_SETUP_SOLVED_BIT_OFFSET)) != 0) {
            state[WCBEACON_STATE_PHASE] = WCBEACON_PHASE_ACTIVE;
        } else {
            state[WCBEACON_STATE_PHASE] = WCBEACON_PHASE_WAITING_FOR_TRICKY;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
