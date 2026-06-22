#ifndef MAIN_DLL_DBSTEALERWORMCONTROL_STRUCT_H_
#define MAIN_DLL_DBSTEALERWORMCONTROL_STRUCT_H_

#include "types.h"

typedef struct DbStealerwormControl
{
    int cfg; /* entry in the lbl_80329514 table (stride 8 ints) */
    f32 unk04;
    f32 unk08;
    f32 countdown; /* countdown; init randomGetRange(10, 300) */
    f32 nextSfxTime; /* countdown threshold; on cross plays sfx, advances by randomGetRange(50,250) */
    u8 flags14; /* bits 1/2 */
    u8 flags15; /* bits 1/4 */
    u8 unk16[2];
    int linkedObj; /* ObjMsg target object */
    s16 unk1C;
    u8 unk1E[2];
    int routeCursor; /* cursor into the cfg route list (12-byte entries) */
    int msgStack; /* Stack_* handle; 3-word messages */
    int unk28;
    int unk2C;
    int unk30; /* ObjGroup id */
    u8 unk34;
    u8 unk35[3];
    f32 unk38;
    int unk3C;
    u8 unk40[4];
    u8 flags44; /* bits 0x10/0x20 */
    u8 unk45[3];
    f32 randomTimer48; /* RandomTimer_UpdateRangeTrigger slots */
    f32 randomTimer4C;
} DbStealerwormControl;

#endif
