#ifndef MAIN_DLL_DR_SHSTAFF_STATE_H_
#define MAIN_DLL_DR_SHSTAFF_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* sh_staff per-object extra state (sh_staff_getExtraSize == 0x74; the
 * returner lives in IM/IMsnowbike.c, the handlers in DR/DRearthwalk.c —
 * IMsnowbike's sh_staff_free walks the slots region with a stride
 * walker and stays raw). Offsets derived from the DRearthwalk census
 * (task #4 redo). */
typedef struct ShStaffState {
    u8 phase;        /* 0x00: 0 idle, 1 armed, 3/4/5 carry-render modes, 6 done */
    u8 hudFlag;      /* 0x01 */
    u8 flags;        /* 0x02: 1/4 = spawn columns, 2/8 = columns full, 0x10 fade, 0x20 converge */
    u8 mapLoaded;    /* 0x03 */
    f32 fadeTimer;   /* 0x04 */
    f32 carryMtx[12];/* 0x08: player-relative carry transform */
    int slots[10];   /* 0x38: spawned haze objects */
    u8 pending[10];  /* 0x60: per-slot respawn requests */
    u8 pad6A[2];
    f32 pulseTimer;  /* 0x6c */
    f32 sfxTimer;    /* 0x70 */
} ShStaffState;
STATIC_ASSERT(sizeof(ShStaffState) == 0x74);

#endif /* MAIN_DLL_DR_SHSTAFF_STATE_H_ */
