/* DLL 0x1B8 - SCTotemPole [801DBFA0-801DC310).
 * The four LightFoot Village totem poles - the "Tracking Test". Each pole's
 * lit state is one GameBit: FRONT 0x81 / LEFT 0x82 / RIGHT 0x83 / REAR 0x84
 * (reset by sclevelcontrol on entry). Lighting all four plays the success
 * fanfare; the test is timed (beat MuscleFoot's record). */
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/dll/SC/sc_shared.h"
#include "main/dll/SC/dll_01B8_sctotempole.h"
#include "main/dll/SC/dll_01B9_sccloudrunnera.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/obj_list.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/model_engine.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

u16 gSCTotemPoleRecordGameBits[4] = {0x2B7, 0x2CB, 0x2CC, 0};

int gSCTotemPoleHitCooldown;

#define SC_TOTEMPOLE_GAMEBIT_FRONT 0x81
#define SC_TOTEMPOLE_GAMEBIT_LEFT 0x82
#define SC_TOTEMPOLE_GAMEBIT_RIGHT 0x83
#define SC_TOTEMPOLE_GAMEBIT_REAR 0x84
#define SC_TOTEMPOLE_MAP_ID_REAR 0x44916
#define SC_TOTEMPOLE_MAP_ID_RIGHT 0x44909
#define SC_TOTEMPOLE_MAP_ID_FRONT 0x4490C
#define SC_TOTEMPOLE_MAP_ID_LEFT 0x4490F

#define SC_TOTEMPOLE_EVENT_ALL_LIT 6      /* peer event: all four poles lit */

/* Insert newTime into the three sorted record-time GameBits (ascending,
   zero = empty slot); returns whether the order changed. */
int sc_totempole_sortCompletionGameBits(recordBits, newTime)
u16* recordBits;
u16 newTime;
{
    u16 times[4];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++)
    {
        u16 v = mainGetBit(recordBits[i]);
        times[i] = v;
    }
    times[3] = newTime;
    for (j = 0; j < 3; j++)
    {
        for (i = 0; i < 3; i++)
        {
            if (times[i + 1] != 0)
            {
                if ((times[i + 1] < times[i]) || (times[i] == 0))
                {
                    u16 tmp = times[i];
                    times[i] = times[i + 1];
                    times[i + 1] = tmp;
                    changed = 1;
                }
            }
        }
    }
    for (i = 0; i < 3; i++)
    {
        mainSetBits(recordBits[i], times[i]);
    }
    return changed;
}

int sc_totempole_getExtraSize(void) { return sizeof(SCTotemPoleState); }
int sc_totempole_getObjectTypeId(void) { return 0x0; }

void sc_totempole_free(void)
{
}

void sc_totempole_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void sc_totempole_hitDetect(void)
{
}

void sc_totempole_update(GameObject* obj)
{
    SCTotemPoleState* state = obj->extra;
    ObjAnimEventList animEvents;
    int playedFanfare;
    GameObject** objects;
    int objCount;
    int i;

    state->previousState = state->currentState;
    state->currentState = mainGetBit(state->gameBit);
    if (state->previousState != state->currentState)
    {
        if (state->currentState != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_cflap2_c);
            state->animSpeed = 0.01f;
            playedFanfare = 0;
            if (mainGetBit(SC_TOTEMPOLE_GAMEBIT_FRONT) != 0 &&
                mainGetBit(SC_TOTEMPOLE_GAMEBIT_LEFT) != 0 &&
                mainGetBit(SC_TOTEMPOLE_GAMEBIT_RIGHT) != 0 &&
                mainGetBit(SC_TOTEMPOLE_GAMEBIT_REAR) != 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                playedFanfare = 1;
                objects = (GameObject**)ObjList_GetObjects(&i, &objCount);
                for (; i < objCount; i++)
                {
                    if (objects[i] != obj && objects[i]->anim.seqId == SC_SEQ_TOTEMPOLE)
                    {
                        (*(SCTotemPoleInterfaceVTable**)objects[i]->anim.dll)->handleEvent(
                            objects[i], SC_TOTEMPOLE_EVENT_ALL_LIT);
                        break;
                    }
                }
                sc_totempole_sortCompletionGameBits(gSCTotemPoleRecordGameBits,
                                                     (s32)(gameTimerGetElapsedMilliseconds() / 10.0f));
            }
            if (!playedFanfare)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }
        else
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_cflap2_c);
            state->animSpeed = -0.01f;
        }
    }
    ObjAnim_AdvanceCurrentMove((int)obj, state->animSpeed, timeDelta, &animEvents);
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                               (f32*)&gSCTotemPoleHitCooldown);
}

void sc_totempole_init(GameObject* obj, SCTotemPolePlacement* placement)
{
    SCTotemPoleState* state = obj->extra;
    switch (placement->head.mapId)
    {
    case SC_TOTEMPOLE_MAP_ID_REAR:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_REAR;
        break;
    case SC_TOTEMPOLE_MAP_ID_RIGHT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_RIGHT;
        break;
    case SC_TOTEMPOLE_MAP_ID_FRONT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_FRONT;
        break;
    case SC_TOTEMPOLE_MAP_ID_LEFT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_LEFT;
        break;
    }
    obj->anim.rotX = (s16)((u32)placement->yaw << 8);
}

void sc_totempole_release(void)
{
}

void sc_totempole_initialise(void)
{
}

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
ObjectDescriptor gSC_CloudrunnerAObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)sc_cloudrunnera_initialise,
    (ObjectDescriptorCallback)sc_cloudrunnera_release,
    0,
    (ObjectDescriptorCallback)sc_cloudrunnera_init,
    (ObjectDescriptorCallback)sc_cloudrunnera_update,
    (ObjectDescriptorCallback)sc_cloudrunnera_hitDetect,
    (ObjectDescriptorCallback)sc_cloudrunnera_render,
    (ObjectDescriptorCallback)sc_cloudrunnera_free,
    (ObjectDescriptorCallback)sc_cloudrunnera_getObjectTypeId,
    sc_cloudrunnera_getExtraSize,
};
