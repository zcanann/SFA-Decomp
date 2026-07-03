/* DLL 0x1B8 - SCTotemPole [801DBFA0-801DC310).
 * The four LightFoot Village totem poles — the "Tracking Test". Each pole's
 * lit state is one GameBit: FRONT 0x81 / LEFT 0x82 / RIGHT 0x83 / REAR 0x84
 * (reset by sclevelcontrol on entry). Lighting all four plays the success
 * fanfare; the test is timed (beat MuscleFoot's record). */
#include "main/obj_placement.h"
#include "main/dll/scmusictreesetup_struct.h"
#include "main/dll/SC/sc_shared.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

extern f32 fn_8001461C(void);
extern int lbl_803DC068;    /* tracking-test record-time GameBit id table */
extern int lbl_803DDC08;
extern f32 lbl_803E55D0;    /* render fade alpha */
extern f32 lbl_803E55D4;    /* anim speed when a pole lights */
extern f32 lbl_803E55D8;    /* completion-time score divisor */
extern f32 lbl_803E55DC;    /* anim speed when a pole goes dark */

STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

typedef struct SCTotemPoleState
{
    u16 gameBit;       /* 0x00: this pole's lit-state GameBit */
    u8 currentState;   /* 0x02: lit (1) / unlit (0) this frame */
    u8 previousState;  /* 0x03: lit state last frame, for edge detection */
    f32 animSpeed;     /* 0x04: light / extinguish anim playback speed */
} SCTotemPoleState;

#define SC_TOTEMPOLE_GAMEBIT_FRONT 0x81
#define SC_TOTEMPOLE_GAMEBIT_LEFT 0x82
#define SC_TOTEMPOLE_GAMEBIT_RIGHT 0x83
#define SC_TOTEMPOLE_GAMEBIT_REAR 0x84
#define SC_TOTEMPOLE_SETUP_REAR 0x44916
#define SC_TOTEMPOLE_SETUP_RIGHT 0x44909
#define SC_TOTEMPOLE_SETUP_FRONT 0x4490C
#define SC_TOTEMPOLE_SETUP_LEFT 0x4490F

#define SC_TOTEMPOLE_EVENT_ALL_LIT 6      /* peer event: all four poles lit */

/* Insert newTime into the three sorted record-time GameBits (ascending,
   zero = empty slot); returns whether the order changed. */
int sc_totempole_sortCompletionGameBits(u16* recordBits, u16 newTime)
{
    u16 times[4];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++)
    {
        u16 v = GameBit_Get(recordBits[i]);
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
        GameBit_Set(recordBits[i], times[i]);
    }
    return changed;
}

int sc_totempole_getExtraSize(void) { return 0x8; }
int sc_totempole_getObjectTypeId(void) { return 0x0; }

void sc_totempole_free(void)
{
}

void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E55D0);
}

void sc_totempole_hitDetect(void)
{
}

void sc_totempole_update(int obj)
{
    SCTotemPoleState* state = ((GameObject*)obj)->extra;
    f32 animEvents[8];
    int playedFanfare;
    int* objects;
    int objCount;
    int i;

    state->previousState = state->currentState;
    state->currentState = GameBit_Get(state->gameBit);
    if (state->previousState != state->currentState)
    {
        if (state->currentState != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_cflap2_c);
            state->animSpeed = lbl_803E55D4;
            playedFanfare = 0;
            if (GameBit_Get(SC_TOTEMPOLE_GAMEBIT_FRONT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_LEFT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_RIGHT) != 0 &&
                GameBit_Get(SC_TOTEMPOLE_GAMEBIT_REAR) != 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                playedFanfare = 1;
                objects = ObjList_GetObjects(&i, &objCount);
                for (; i < objCount; i++)
                {
                    if ((void*)objects[i] != (void*)obj &&
                        ((GameObject*)objects[i])->anim.seqId == SC_SEQ_TOTEMPOLE)
                    {
                        (*(void (**)(int, int))(*(int*)&((GameObject*)objects[i])->anim.dll[0] +
                                                SC_VT_HANDLE_EVENT))(
                            objects[i], SC_TOTEMPOLE_EVENT_ALL_LIT);
                        break;
                    }
                }
                ((int (*)(u16*, int))sc_totempole_sortCompletionGameBits)(
                    (u16*)&lbl_803DC068, (s32)(fn_8001461C() / lbl_803E55D8));
            }
            if (!playedFanfare)
            {
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_cflap2_c);
            state->animSpeed = lbl_803E55DC;
        }
    }
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta,
                                                                (ObjAnimEventList*)&animEvents);
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (f32*)&lbl_803DDC08);
}

void sc_totempole_init(int obj, int p2)
{
    SCTotemPoleState* state = ((GameObject*)obj)->extra;
    switch (((ObjPlacement*)p2)->mapId)
    {
    case SC_TOTEMPOLE_SETUP_REAR:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_REAR;
        break;
    case SC_TOTEMPOLE_SETUP_RIGHT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_RIGHT;
        break;
    case SC_TOTEMPOLE_SETUP_FRONT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_FRONT;
        break;
    case SC_TOTEMPOLE_SETUP_LEFT:
        state->gameBit = SC_TOTEMPOLE_GAMEBIT_LEFT;
        break;
    }
    ((GameObject*)obj)->anim.rotX = (s16)((u32)((SCMusicTreeSetup*)p2)->yawByte << 8);
}

void sc_totempole_release(void)
{
}

void sc_totempole_initialise(void)
{
}
