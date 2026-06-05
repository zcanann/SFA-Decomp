#include "main/dll/dll_80220608_shared.h"

#define SFXmn_sml_trex_fstep 126

#pragma peephole on
#pragma scheduling on
int timer_getExtraSize(void) { return 0x20; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void timer_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x4c);
    if (*(void **)(state + 4) != NULL) {
        fn_8001CB3C(state + 4);
    }
    gameTimerStop();
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int timer_hasExpired(int obj)
{
    int state = *(int *)(obj + 0xb8);
    return ((TimerFlags *)(state + 0xd))->expired;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int timer_isEffectMode(int obj)
{
    int state = *(int *)(obj + 0xb8);
    return *(u8 *)(state + 0xc) == 2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void timer_clearManualFlags(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((TimerFlags *)(state + 0xd))->manual = 0;
    ((TimerFlags *)(state + 0xd))->expired = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void timer_forceStart(int obj)
{
    int state = *(int *)(obj + 0xb8);
    ((TimerFlags *)(state + 0xd))->manual = 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void timer_addDuration(int obj, int duration)
{
    int state = *(int *)(obj + 0xb8);
    if (fn_80080150(state) != 0) {
        *(f32 *)(state + 0) = *(f32 *)(state + 0) + (f32)duration;
        if (*(u8 *)(state + 0xc) == 1) {
            gameTimerInit(0x1d, (int)(*(f32 *)(state + 0) / lbl_803E7408));
            timerSetToCountUp();
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void timer_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    void *light = *(void **)(*(int *)(obj + 0xb8) + 4);
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 &&
        *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
    if (*(void **)(obj + 0xc4) == NULL) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7418);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void timer_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    storeZeroToFloatParam((void *)state);
    *(u8 *)(state + 0xc) = *(u8 *)(setup + 0x19);
    *(f32 *)(state + 8) = lbl_803E7424;
    ((TimerFlags *)(state + 0xd))->expired = 0;
    ((TimerFlags *)(state + 0xd))->manual = 0;
    *(int *)(state + 4) = 0;
    ObjGroup_AddObject(obj, 0x4c);
    ((TimerFlags *)(state + 0xd))->flag20 = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void timer_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    TimerFlags *f = (TimerFlags *)(state + 0xd);
    int flag;

    if (fn_80080150(state) != 0) {
        flag = 0;
        if (f->manual == 0 && (u32)GameBit_Get(*(s16 *)(setup + 0x20)) == 0) {
            storeZeroToFloatParam((void *)state);
            if (*(u8 *)(state + 0xc) == 1) {
                if (*(int *)(*(int *)(obj + 0x4c) + 0x14) != 0x466ED) {
                    Sfx_PlayFromObject(obj, SFXmn_sml_trex_fstep);
                }
            }
            flag = 1;
        }
        if (timerCountDown((void *)state) != 0) {
            GameBit_Set(*(s16 *)(setup + 0x1e), 1);
            GameBit_Set(*(s16 *)(setup + 0x20), 0);
            flag = 1;
        }
        if (flag != 0) {
            f->expired = 1;
            switch (*(u8 *)(state + 0xc)) {
            case 1:
                gameTimerStop();
                break;
            case 2:
                fn_8001CB3C(state + 4);
                break;
            }
            f->manual = 0;
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0 || f->manual != 0) {
            storeZeroToFloatParam((void *)state);
            if (*(s16 *)(setup + 0x1a) != 0) {
                s16toFloat((void *)state, (s16)(*(s16 *)(setup + 0x1a) * 60));
            }
            switch (*(u8 *)(state + 0xc)) {
            case 1:
                gameTimerInit(29, *(s16 *)(setup + 0x1a));
                timerSetToCountUp();
                break;
            case 2:
                *(int *)(state + 4) = fn_8001CC9C(obj, 255, 0, 0, 0);
                if (*(int *)(state + 4) != 0) {
                    modelLightStruct_setupGlow((void *)*(int *)(state + 4), 0, 255, 0, 0, 100, lbl_803DC418);
                    lightVecFn_8001dd88((void *)*(int *)(state + 4), lbl_803E741C, lbl_803E7420,
                                        lbl_803E741C);
                }
                break;
            }
        }
        if (*(u8 *)(state + 0xc) == 2 && fn_80080150(state) != 0) {
            int hold = *(int *)(state + 4);
            int tv = (int)((f32)(*(s16 *)(setup + 0x1a) * 60) / *(f32 *)(state + 0) *
                           lbl_803DC41C);
            int *texPtr = objFindTexture(obj, 0, 0);
            int v;
            if (texPtr != 0) {
                v = *texPtr + tv * framesThisStep;
                if (v > 512) {
                    v -= 512;
                }
                *texPtr = v;
            }
            if (hold != 0) {
                tv = v >> 8;
            } else {
                tv = 0;
            }
            if (*(int *)(state + 4) != 0) {
                if (tv == 1 && tv != f->flag20) {
                    Sfx_PlayFromObject(obj, 986);
                }
                lightFn_8001db6c((void *)*(int *)(state + 4), (u8)tv, lbl_803E741C);
            }
            f->flag20 = (u8)tv;
        }
        if (*(int *)(state + 4) != 0) {
            modelLightStruct_updateGlowAlpha((void *)*(int *)(state + 4));
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
