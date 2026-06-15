/* DLL 0x01A3 - NW animated-ice objects [801CF78C-801CF7E8) */
#include "main/objlib.h"

#include "main/game_object.h"

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

int nw_animice_SeqFn(void) { return 0x0; }
int nw_animice_getExtraSize(void) { return 0x0; }
int nw_animice_getObjectTypeId(void) { return 0x0; }
int nw_ice_getExtraSize(void);

void nw_animice_free(int x) { ObjGroup_RemoveObject(x, 0x3d); }
void nw_ice_free(int x);

void nw_animice_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)nw_animice_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    ObjGroup_AddObject((u32)obj, 0x3d);
}
