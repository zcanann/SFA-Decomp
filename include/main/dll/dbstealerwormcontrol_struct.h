#ifndef MAIN_DLL_DBSTEALERWORMCONTROL_STRUCT_H_
#define MAIN_DLL_DBSTEALERWORMCONTROL_STRUCT_H_

#include "types.h"

/* DbStealerwormControl.flags14: per-frame effect-request bits, consumed and
 * cleared each tick by the fx dispatcher (fn_80203000). */
#define DBWORM_FLAG14_ATTACK  0x1 /* strike the current target this frame */
#define DBWORM_FLAG14_FX_DUST 0x2 /* emit the small dust burst (partfx 0x345) */
#define DBWORM_FLAG14_FX_SPRAY 0x4 /* emit the large spray burst (partfx 0x343 x10) */

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
    s16 msgSlotIndex; /* queued message-config slot index (-1 = none); pushed as the type-7 frame payload */
    u8 unk1E[2];
    int routeCursor; /* cursor into the cfg route list (12-byte entries) */
    int msgStack; /* Stack_* handle; 3-word messages */
    int msgCode; /* current message word 0: code dispatched to the player interface (frame[0]) */
    int msgMode; /* current message word 1: target-acquisition mode 0/1 (frame[1]) */
    int objGroup; /* current message word 2: ObjGroup id for FindNearest/Contains (frame[2]) */
    u8 msgAdvance; /* set to advance to / pop the next queued message next tick */
    u8 unk35[3];
    f32 spawnAccumulator; /* 0x38: accumulates on worm move-done; when over threshold, triggers a spawn-search and subtracts the threshold */
    int savedTargetObj; /* cached target-object handle (pointer-spelled; NULL-checked) */
    u8 unk40[4];
    u8 flags44; /* bits 0x10/0x20 */
    u8 unk45[3];
    f32 randomTimer48; /* RandomTimer_UpdateRangeTrigger slots */
    f32 randomTimer4C;
} DbStealerwormControl;

#endif
