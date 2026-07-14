#include "main/dll/boulder.h"
#include "main/dll/dll_020B_firefly.h"

void fn_801F4ECC(GameObject* obj, BoulderShakeRec* record)
{
    record->histX0 = record->histX1;
    record->histY0 = record->histY1;
    record->histZ0 = record->histZ1;
    record->histX1 = record->histX2;
    record->histY1 = record->histY2;
    record->histZ1 = record->histZ2;
    record->histX2 = record->histX3;
    record->histY2 = record->histY3;
    record->histZ2 = record->histZ3;
    record->amplitude = lbl_803E5ED8 * (f32)(s32)randomGetRange(0xa0, 0xb4);
    record->histX3 = record->liveX;
    record->histY3 = record->liveY;
    record->histZ3 = record->liveZ;
}
