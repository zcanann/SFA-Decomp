#include "main/dll/WM/wm_shared.h"
#include "main/mapEvent.h"

typedef struct WmSeqPointState {
    f32 radius;
    s16 requiredGameBit;
    s16 gateGameBit;
    s16 triggerId;
    s16 unk0A;
    u8 command;
    u8 done;
    u8 mode;
    u8 skyWasOn;
} WmSeqPointState;

void fn_801F654C(int obj)
{
    WmSeqPointState *state;
    int skyOn;

    state = *(WmSeqPointState **)(obj + 0xb8);
    if (state->triggerId == 0x21) {
        GameBit_Set(0xd1b, 1);
    } else if (state->triggerId == 1) {
        skyOn = getSkyColorFn_80088e08(0) & 0xff;
        if (state->skyWasOn != 0 && skyOn == 0) {
            getEnvfxActImmediately(0, 0, 0x22d, 0);
            getEnvfxActImmediately(obj, obj, 0x22c, 0);
            getEnvfxActImmediately(obj, obj, 0x229, 0);
            getEnvfxActImmediately(obj, obj, 0x22a, 0);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 4, 1);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 10, 0);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 0xb, 0);
        } else if (state->skyWasOn == 0 && skyOn != 0) {
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(obj, obj, 0x216, 0);
            getEnvfxActImmediately(obj, obj, 0x84, 0);
            getEnvfxActImmediately(obj, obj, 0x8a, 0);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 4, 0);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 10, 1);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 0xb, 1);
        }
    }
}

int fn_801F6750(int obj, int unused, int actor)
{
    WmSeqPointState *state;
    int player;
    int i;
    u8 action;

    state = *(WmSeqPointState **)(obj + 0xb8);
    player = (int)Obj_GetPlayerObject();
    *(u8 *)(actor + 0x56) = 0;
    *(void **)(actor + 0xe8) = fn_801F654C;

    for (i = 0; i < *(u8 *)(actor + 0x8b); i++) {
        action = *(u8 *)(actor + i + 0x81);
        if (state->triggerId == 0) {
            if (action != 0) {
                state->command = action;
                switch (action) {
                    case 1:
                        GameBit_Set(0x143, 1);
                        break;
                    case 2:
                        GameBit_Set(0x143, 0);
                        break;
                    case 4:
                        GameBit_Set(0x21d, 1);
                        fn_80296518(player, 8, 0);
                        GameBit_Set(0x277, 1);
                        break;
                    case 5:
                        GameBit_Set(0x21d, 1);
                        break;
                    default:
                        break;
                }
            }
        } else if (action == 0xb) {
            if ((getSkyColorFn_80088e08(0) & 0xff) != 0) {
                getEnvfxActImmediately(0, 0, 0x217, 0);
                getEnvfxActImmediately(obj, obj, 0x216, 0);
                getEnvfxActImmediately(obj, obj, 0x84, 0);
                getEnvfxActImmediately(obj, obj, 0x8a, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 4, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 10, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 0xb, 1);
            }
        } else if (action == 0xa) {
            if ((getSkyColorFn_80088e08(0) & 0xff) == 0) {
                getEnvfxActImmediately(0, 0, 0x22d, 0);
                getEnvfxActImmediately(obj, obj, 0x22c, 0);
                getEnvfxActImmediately(obj, obj, 0x229, 0);
                getEnvfxActImmediately(obj, obj, 0x22a, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 4, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 10, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(*(s8 *)(obj + 0xac), 0xb, 0);
            }
        }
        *(u8 *)(actor + i + 0x81) = 0;
    }

    return 0;
}

int wmseqpoint_getExtraSize(void) { return 0x10; }

int wmseqpoint_getObjectTypeId(void) { return 0x0; }

void wmseqpoint_free(void) {}

#pragma peephole off
void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderFn_8003b8f4(lbl_803E5F10);
    }
}
#pragma peephole reset

void wmseqpoint_hitDetect(void) {}

void wmseqpoint_update(int obj)
{
    WmSeqPointState *state;
    int player;
    int target;
    int i;

    player = (int)Obj_GetPlayerObject();
    state = *(WmSeqPointState **)(obj + 0xb8);

    if (state->gateGameBit != -1) {
        if (state->done != 0) {
            if (GameBit_Get(state->gateGameBit) != 0) {
                return;
            }
            GameBit_Set(state->gateGameBit, 1);
            state->done = 1;
            return;
        }
        if (GameBit_Get(state->gateGameBit) != 0) {
            state->done = 1;
            return;
        }
    }

    if (state->done != 0) {
        return;
    }

    switch (state->mode) {
        case 0:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 1:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                if (state->triggerId == 0x22) {
                    for (i = 0; i < 5; i++) {
                        GameBit_Set(lbl_80328CC8[i * 2], 0);
                        target = ObjList_FindObjectById(lbl_80328CC8[i * 2 + 1]);
                        *(u8 *)(*(int *)(target + 0xb8) + 0xd) = 0;
                        if (*(s16 *)(target + 0xb4) != -1) {
                            (*(void (**)(int))(*gObjectTriggerInterface + 0x4c))(*(s16 *)(target + 0xb4));
                        }
                    }
                } else if (state->triggerId == 1) {
                    state->skyWasOn = (u8)getSkyColorFn_80088e08(0);
                }
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 2:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius &&
                state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                if (state->triggerId == 0x21) {
                    GameBit_Set(0xd1b, 0);
                    target = ObjList_FindObjectById(0x4aeb1);
                    *(u8 *)(*(int *)(target + 0xb8) + 0xd) = 0;
                    if (*(s16 *)(target + 0xb4) != -1) {
                        (*(void (**)(int))(*gObjectTriggerInterface + 0x4c))(*(s16 *)(target + 0xb4));
                    }
                }
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 3:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius &&
                state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) == 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                GameBit_Set(state->requiredGameBit, 1);
                state->done = 1;
            }
            break;
        case 4:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) == 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                GameBit_Set(state->requiredGameBit, 1);
                state->done = 1;
            }
            break;
        case 5:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
            }
            break;
        default:
            break;
    }
}

void wmseqpoint_init(int obj, int setup)
{
    WmSeqPointState *state;

    state = *(WmSeqPointState **)(obj + 0xb8);
    *(void **)(obj + 0xbc) = fn_801F6750;
    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    state->radius = (f32)*(s16 *)(setup + 0x1a);
    state->triggerId = *(s16 *)(setup + 0x1c);
    state->done = 0;
    state->mode = *(u8 *)(setup + 0x19);
    state->requiredGameBit = *(s16 *)(setup + 0x1e);
    state->gateGameBit = *(s16 *)(setup + 0x20);
    state->command = 0;
    state->unk0A = 0;
}

void wmseqpoint_release(void) {}

void wmseqpoint_initialise(void) {}
