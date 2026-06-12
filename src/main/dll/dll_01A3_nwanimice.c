/* DLL 0x01A3 — NW animated-ice objects [801CF78C-801CF7E8) */
#include "main/dll/dim2conveyor.h"
#include "main/gameplay_runtime.h"

extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();

#include "main/dll/creator1D6.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

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
