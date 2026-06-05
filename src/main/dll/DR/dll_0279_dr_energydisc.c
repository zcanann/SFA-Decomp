#include "main/dll/dll_80220608_shared.h"

#include "main/audio/sfx_ids.h"
int drenergydisc_getExtraSize(void) { return 1; }

int drenergydisc_getObjectTypeId(void) { return 0; }

void drenergydisc_free(void) {}

void drenergydisc_render(void) {}

void drenergydisc_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
void drenergydisc_update(int obj)
{
    int *texture;
    DrEnergyDiscState *state = *(DrEnergyDiscState **)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if (state->activated == 0) {
            state->activated = 1;
            Sfx_PlayFromObject(obj, SFXfend_rob_servo2);
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }

        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *(s16 *)((char *)texture + 0xa) =
                *(s16 *)((char *)texture + 0xa) + lbl_803DC380 * framesThisStep;
            if (*(s16 *)((char *)texture + 0xa) < -0x1000) {
                *(s16 *)((char *)texture + 0xa) = 0;
            }
        }
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6BB0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drenergydisc_init(u8 *obj, u8 *setup)
{
    int *texture;
    DrEnergyDiscState *state = *(DrEnergyDiscState **)(obj + 0xb8);
    s16 objType;

    objType = (s16)((s8)setup[0x18] << 8);
    *(s16 *)obj = objType;
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        state->activated = 1;
        Sfx_PlayFromObject((int)obj, SFXfend_rob_servo2);
        texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    } else {
        state->activated = 0;
        texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
    }
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x6000);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drenergydisc_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drenergydisc_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
