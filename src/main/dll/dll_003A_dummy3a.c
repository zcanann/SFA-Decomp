/*
 * dummy3a (DLL 0x3A) - a stub game object whose lifecycle hooks
 * (render / frameStart / frameEnd / release / initialise) are all empty;
 * frameStart simply returns 0. The object does nothing per frame.
 *
 * The two FUN_8011daf8/FUN_8011dafc helpers compiled into this unit are
 * spillover from the adjacent dimenu debug code: FUN_8011dafc throttles a
 * repeating action via a signed countdown in DAT_803de3a8, decremented each
 * call by DAT_803dc070 (clamped to 3); when the countdown reaches zero it
 * fires FUN_80053c98. Names/types of those symbols are not established, so
 * they are left as imported.
 */
#include "main/dll/debug/dimenu.h"

extern undefined8 FUN_80006b84();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80053c98();

extern undefined4 DAT_803dc070; /* per-call decrement amount (clamped to 3) */
extern undefined4 DAT_803de3a8; /* signed countdown timer */

void FUN_8011daf8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, undefined4 param_11, undefined4 param_12,
                  undefined4 param_13, undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
}

undefined4
FUN_8011dafc(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    byte decrement;
    undefined8 target;

    FUN_80017a98();
    decrement = DAT_803dc070;
    if (3 < DAT_803dc070)
    {
        decrement = 3;
    }
    if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - decrement, DAT_803de3a8 < '\x01'))
    {
        target = FUN_80006b84(1);
        FUN_80053c98(target, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x60, '\x01',
                     param_11, param_12, param_13, param_14, param_15, param_16);
    }
    return 0;
}

void Dummy3A_render(void)
{
}

void Dummy3A_frameEnd(void)
{
}

void Dummy3A_release(void)
{
}

void Dummy3A_initialise(void)
{
}

int Dummy3A_frameStart(void) { return 0; }
