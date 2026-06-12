#include "main/dll/mmp_asteroid_re.h"
#include "main/game_object.h"

typedef struct CfDoorlightObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 frameStep;
    u8 pad1E[0x20 - 0x1E];
} CfDoorlightObjectDef;


extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* objFindTexture(void* obj, int target, int param_3);


typedef struct CfDoorLightState
{
    s32 textureId;
    u8 frameStep;
    u8 pad05[0x8 - 0x5];
    s32 maxFrame;
    s32 resetFrame;
    s32 currentFrame;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightDef
{
    u8 pad00[0x1e];
    s16 doneEvent;
    s16 triggerEvent;
} CfDoorLightDef;


/*
 * --INFO--
 *
 * Function: transporter_init
 * EN v1.0 Address: 0x801916A0
 * EN v1.0 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->flags per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->flags & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */

/*
 * --INFO--
 *
 * Function: FUN_801916e8
 * EN v1.0 Address: 0x801916E8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191BD4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80191730
 * EN v1.0 Address: 0x80191730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191C1C
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/* Trivial 4b 0-arg blr leaves. */









void cf_doorlight_free(void)
{
}

void cf_doorlight_render(void)
{
}

void cf_doorlight_hitDetect(void)
{
}

void cf_doorlight_release(void)
{
}

void cf_doorlight_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int cflightwall_getExtraSize(void);
int cf_doorlight_getExtraSize(void) { return 0x18; }
int cf_doorlight_getObjectTypeId(void) { return 0x0; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3EE8;





void cf_doorlight_update(int obj)
{
    CfDoorLightState* state;
    CfDoorLightDef* def;
    int* textureFrame;

    state = ((GameObject*)obj)->extra;
    def = *(CfDoorLightDef**)&((GameObject*)obj)->anim.placementData;
    if ((((state->flags >> 5) & 1) == 0) && (GameBit_Get(def->triggerEvent) != 0) &&
        (((state->flags >> 6) & 1) == 0))
    {
        state->flags = (state->flags & ~0x20) | 0x20;
        state->currentFrame = 0;
    }
    if (((state->flags >> 5) & 1) != 0)
    {
        textureFrame = objFindTexture((void*)obj, state->textureId, 0);
        if (textureFrame != 0)
        {
            state->currentFrame += state->frameStep;
            if (state->currentFrame < 0)
            {
                state->currentFrame = 0;
            }
            else if (state->currentFrame > state->maxFrame)
            {
                if (def->doneEvent == -1)
                {
                    state->currentFrame = state->resetFrame;
                }
                else
                {
                    GameBit_Set(def->doneEvent, 1);
                    state->flags = state->flags & ~0x20;
                    state->flags = (state->flags & ~0x40) | 0x40;
                    state->currentFrame = state->maxFrame;
                }
            }
            *textureFrame = state->currentFrame;
        }
    }
}

void cf_doorlight_init(int* obj, s8* def)
{
    register CfDoorLightState* state = ((GameObject*)obj)->extra;
    u32 b;
    state->textureId = 0;
    *(s16*)obj = (s16)((s32)def[0x19] << 9);
    state->maxFrame = (int)((CfDoorlightObjectDef*)def)->unk1A << 8;
    state->frameStep = (u8)((CfDoorlightObjectDef*)def)->frameStep;
    state->resetFrame = (int)def[0x18] << 8;
    b = (u32)(u8)
    GameBit_Get(((CfDoorLightDef*)def)->doneEvent);
    state->flags = (u8)((state->flags & ~0x40) | ((b & 1) << 6));
    if (((u32)state->flags >> 6) & 1)
    {
        state->currentFrame = state->maxFrame;
        state->flags |= 0x20;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->objectFlags |= 0x4000;
}
