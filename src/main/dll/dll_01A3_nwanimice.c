/* DLL 0x01A3 — NW animated-ice objects [801CF78C-801CF7E8) */
#include "main/dll/dim2conveyor.h"
#include "main/gameplay_runtime.h"

extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();







/*
 * --INFO--
 *
 * Function: nw_mammoth_update
 * EN v1.0 Address: 0x801CF0AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF2E0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: nw_mammoth_init
 * EN v1.0 Address: 0x801CF4F0
 * EN v1.0 Size: 668b
 */


/*
 * --INFO--
 *
 * Function: FUN_801cf0b4
 * EN v1.0 Address: 0x801CF0B4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CF570
 * EN v1.1 Size: 84b
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
 * Function: nw_tricky_getExtraSize
 * EN v1.0 Address: 0x801CF7B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: nw_tricky_SeqFn
 * EN v1.0 Address: 0x801CF78C
 * EN v1.0 Size: 44b
 */

/*
 * --INFO--
 *
 * Function: FUN_801cf108
 * EN v1.0 Address: 0x801CF108
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801CF5C4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/creator1D6.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"











/*
 * --INFO--
 *
 * Function: nw_tricky_update
 * EN v1.0 Address: 0x801CF7E8
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801CFAC0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset


/* Trivial 4b 0-arg blr leaves. */
void nw_animice_render(void)
{
}

void nw_animice_hitDetect(void)
{
}

void nw_animice_update(void)
{
}

void nw_animice_release(void)
{
}

void nw_animice_initialise(void)
{
}

void nw_ice_render(void);

/* 8b "li r3, N; blr" returners. */
int nw_animice_SeqFn(void) { return 0x0; }
int nw_animice_getExtraSize(void) { return 0x0; }
int nw_animice_getObjectTypeId(void) { return 0x0; }
int nw_ice_getExtraSize(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void nw_animice_free(int x) { ObjGroup_RemoveObject(x, 0x3d); }
void nw_ice_free(int x);


/* call(x, N) wrappers. */


void nw_animice_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)nw_animice_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    ObjGroup_AddObject(obj, 0x3d);
}
