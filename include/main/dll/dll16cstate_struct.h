#ifndef MAIN_DLL_DLL16CSTATE_STRUCT_H_
#define MAIN_DLL_DLL16CSTATE_STRUCT_H_

#include "types.h"

typedef struct Dll16CState
{
    void* linkedObj; /* group-10 object matched by type (364/367) */
    f32 unk04; /* set on anim event 2 */
    f32 snapX; /* path point snapshot taken on anim event 2 */
    f32 snapY;
    f32 snapZ;
    f32 pathPointX; /* path point 1 world position, refreshed in render */
    f32 pathPointY;
    f32 pathPointZ;
    u8 opacity; /* distance fade; 0xFF when unlinked */
    s8 subObjIndex; /* lbl_802C2308 id selector; -1 = clear (anim event 3) */
    s8 subObjIndexApplied;
    u8 pad23;
} Dll16CState;

#endif
