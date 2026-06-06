#include "main/dll/dll_80220608_shared.h"

#define WCTEMPLE_EXTRA_SIZE 8
#define WCTEMPLE_SETUP_TYPE_OFFSET 0x18
#define WCTEMPLE_STATE_TIMER 0x00
#define WCTEMPLE_STATE_TRIGGER_SLOT 0x04
#define WCTEMPLE_ACTIVATION_FLAG 1
#define WCTEMPLE_SEQUENCE_SLOT_CLOSED 0
#define WCTEMPLE_SEQUENCE_SLOT_OPEN 1
#define WCTEMPLE_SEQUENCE_INVALID_ARG -1

#define WCTEMPLE_TIMER(state) (*(f32 *)((state) + WCTEMPLE_STATE_TIMER))
#define WCTEMPLE_TRIGGER_SLOT(state) (*(u8 *)((state) + WCTEMPLE_STATE_TRIGGER_SLOT))

#pragma peephole on
#pragma scheduling on
int wctemple_getExtraSize(void) { return WCTEMPLE_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctemple_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E20);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctemple_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    WCTEMPLE_TIMER(state) -= timeDelta;
    if (WCTEMPLE_TIMER(state) < lbl_803E6E24) {
        WCTEMPLE_TIMER(state) = *(f32 *)&lbl_803E6E24;
    }

    if (WCTEMPLE_TRIGGER_SLOT(state) == WCTEMPLE_SEQUENCE_SLOT_CLOSED) {
        if ((*(u8 *)(obj + 0xaf) & WCTEMPLE_ACTIVATION_FLAG) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                WCTEMPLE_SEQUENCE_SLOT_CLOSED, obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            WCTEMPLE_TRIGGER_SLOT(state) = WCTEMPLE_SEQUENCE_SLOT_OPEN;
        }
    } else {
        if ((*(u8 *)(obj + 0xaf) & WCTEMPLE_ACTIVATION_FLAG) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                WCTEMPLE_SEQUENCE_SLOT_OPEN, obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            WCTEMPLE_TRIGGER_SLOT(state) = WCTEMPLE_SEQUENCE_SLOT_CLOSED;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctemple_init(int obj, int setup)
{
    int angle = (s8)*(u8 *)(setup + WCTEMPLE_SETUP_TYPE_OFFSET);

    *(s16 *)obj = (s16)(angle << 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctemple_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
