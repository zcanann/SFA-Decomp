/*
 * SC_totempol (DLL 0x1B8) - the four LightFoot Village tracking-test
 * totem poles.
 */

#include "dlls/objects/440_SC_totempol.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/model_engine.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/objhits.h"

#define SC_TOTEM_POLE_RECORD_COUNT 3

#define SC_TOTEM_POLE_MAP_ID_REAR  0x44916
#define SC_TOTEM_POLE_MAP_ID_RIGHT 0x44909
#define SC_TOTEM_POLE_MAP_ID_FRONT 0x4490C
#define SC_TOTEM_POLE_MAP_ID_LEFT  0x4490F

#define SC_TOTEM_POLE_EVENT_ALL_LIT 6

#define SC_TOTEM_POLE_HIT_EFFECT_MODE  8
#define SC_TOTEM_POLE_HIT_EFFECT_RED   0xFF
#define SC_TOTEM_POLE_HIT_EFFECT_GREEN 0xFF
#define SC_TOTEM_POLE_HIT_EFFECT_BLUE  0x78

#define SC_TOTEM_POLE_ANIMATION_SPEED     0.01f
#define SC_TOTEM_POLE_RECORD_TIME_DIVISOR 10.0f

u16 gScTotemPoleRecordGameBits[4] = {
    GAMEBIT_LV_TestTrackingBestTime1,
    GAMEBIT_LV_TestTrackingBestTime2,
    GAMEBIT_LV_TestTrackingBestTime3,
    0,
};

f32 gScTotemPoleHitEffectCooldown;

ObjectDescriptor gSC_totempoleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_totempole_initialise,
    (ObjectDescriptorCallback)sc_totempole_release,
    0,
    (ObjectDescriptorCallback)sc_totempole_init,
    (ObjectDescriptorCallback)sc_totempole_update,
    (ObjectDescriptorCallback)sc_totempole_hitDetect,
    (ObjectDescriptorCallback)sc_totempole_render,
    (ObjectDescriptorCallback)sc_totempole_free,
    (ObjectDescriptorCallback)sc_totempole_getObjectTypeId,
    sc_totempole_getExtraSize,
};

// clang-format off
int sc_totempole_sortCompletionGameBits(recordGameBits, completionTime)
const u16* recordGameBits;
u16 completionTime;
{
    // clang-format on
    u16 completionTimes[SC_TOTEM_POLE_RECORD_COUNT + 1];
    u8 recordIndex;
    u8 pass;
    s32 changed = 0;

    for (recordIndex = 0; recordIndex < SC_TOTEM_POLE_RECORD_COUNT; recordIndex++) {
        u16 recordTime = mainGetBit(recordGameBits[recordIndex]);
        completionTimes[recordIndex] = recordTime;
    }
    completionTimes[SC_TOTEM_POLE_RECORD_COUNT] = completionTime;
    for (pass = 0; pass < SC_TOTEM_POLE_RECORD_COUNT; pass++) {
        for (recordIndex = 0; recordIndex < SC_TOTEM_POLE_RECORD_COUNT; recordIndex++) {
            if (completionTimes[recordIndex + 1] != 0) {
                if ((completionTimes[recordIndex + 1] < completionTimes[recordIndex]) ||
                    (completionTimes[recordIndex] == 0)) {
                    u16 previousTime = completionTimes[recordIndex];
                    completionTimes[recordIndex] = completionTimes[recordIndex + 1];
                    completionTimes[recordIndex + 1] = previousTime;
                    changed = 1;
                }
            }
        }
    }
    for (recordIndex = 0; recordIndex < SC_TOTEM_POLE_RECORD_COUNT; recordIndex++) {
        mainSetBits(recordGameBits[recordIndex], completionTimes[recordIndex]);
    }
    return changed;
}

int sc_totempole_getExtraSize(void) {
    return sizeof(ScTotemPoleState);
}

int sc_totempole_getObjectTypeId(void) {
    return 0;
}

void sc_totempole_free(void) {
}

void sc_totempole_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 visibleValue = visible;

    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void sc_totempole_hitDetect(void) {
}

void sc_totempole_update(GameObject* obj) {
    ScTotemPoleState* state = obj->extra;
    ObjAnimEventList animEvents;
    int allPolesLit;
    GameObject** objects;
    int objectCount;
    int objectIndex;

    state->wasLit = state->lit;
    state->lit = mainGetBit(state->litGameBit);
    if (state->wasLit != state->lit) {
        if (state->lit != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_cflap2_c);
            state->animationSpeed = SC_TOTEM_POLE_ANIMATION_SPEED;
            allPolesLit = 0;
            if (mainGetBit(SC_TOTEM_POLE_GAMEBIT_FRONT) != 0 && mainGetBit(SC_TOTEM_POLE_GAMEBIT_LEFT) != 0 &&
                mainGetBit(SC_TOTEM_POLE_GAMEBIT_RIGHT) != 0 && mainGetBit(SC_TOTEM_POLE_GAMEBIT_REAR) != 0) {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                allPolesLit = 1;
                objects = ObjList_GetObjects(&objectIndex, &objectCount);
                for (; objectIndex < objectCount; objectIndex++) {
                    if (objects[objectIndex] != obj && objects[objectIndex]->anim.romDefNo == SC_TOTEM_POLE_SEQUENCE_ID) {
                        (*(ScTotemPoleInterfaceVTable**)objects[objectIndex]->anim.dll)
                            ->handleEvent(objects[objectIndex], SC_TOTEM_POLE_EVENT_ALL_LIT);
                        break;
                    }
                }
                sc_totempole_sortCompletionGameBits(
                    gScTotemPoleRecordGameBits,
                    (s32)(gameTimerGetElapsedMilliseconds() / SC_TOTEM_POLE_RECORD_TIME_DIVISOR));
            }
            if (!allPolesLit) {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        } else {
            Sfx_PlayFromObject(obj, SFXTRIG_cflap2_c);
            state->animationSpeed = -SC_TOTEM_POLE_ANIMATION_SPEED;
        }
    }
    ObjAnim_AdvanceCurrentMove(obj, state->animationSpeed, timeDelta, &animEvents);
    ObjHits_PollPriorityHitEffectWithCooldown(obj, SC_TOTEM_POLE_HIT_EFFECT_MODE, SC_TOTEM_POLE_HIT_EFFECT_RED,
                                              SC_TOTEM_POLE_HIT_EFFECT_GREEN, SC_TOTEM_POLE_HIT_EFFECT_BLUE,
                                              SFXTRIG_swdtest222, &gScTotemPoleHitEffectCooldown);
}

void sc_totempole_init(GameObject* obj, const ScTotemPolePlacement* placement) {
    ScTotemPoleState* state = obj->extra;

    switch (placement->base.ident) {
    case SC_TOTEM_POLE_MAP_ID_REAR:
        state->litGameBit = SC_TOTEM_POLE_GAMEBIT_REAR;
        break;
    case SC_TOTEM_POLE_MAP_ID_RIGHT:
        state->litGameBit = SC_TOTEM_POLE_GAMEBIT_RIGHT;
        break;
    case SC_TOTEM_POLE_MAP_ID_FRONT:
        state->litGameBit = SC_TOTEM_POLE_GAMEBIT_FRONT;
        break;
    case SC_TOTEM_POLE_MAP_ID_LEFT:
        state->litGameBit = SC_TOTEM_POLE_GAMEBIT_LEFT;
        break;
    }
    obj->anim.rotX = (s16)((u32)placement->rotXByte << 8);
}

void sc_totempole_release(void) {
}

void sc_totempole_initialise(void) {
}
