/*
 * nwanimice (DLL 0x1A3) - the animated ice blocks of SnowHorn Wastes
 * (map 'nwastes', 0x0A).
 *
 * These are the moving "source" ice objects: each one registers in the
 * NW_ANIMICE object group so that the static nwice objects (DLL 0x1A4)
 * can find and follow it. The object itself has no per-frame behaviour
 * here - update/render/hitDetect are all stubs; the work lives in nwice.
 */
#include "main/objlib.h"

#include "main/game_object.h"
#include "main/dll/NW/nw_shared.h"

#define NWANIMICE_OBJFLAG_HIDDEN 0x4000
#define NWANIMICE_OBJFLAG_HITDETECT_DISABLED 0x2000

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

int nw_animice_SeqFn(void) { return 0x0; }
int nw_animice_getExtraSize(void) { return 0x0; }
int nw_animice_getObjectTypeId(void) { return 0x0; }

void nw_animice_free(int obj) { ObjGroup_RemoveObject(obj, NW_ANIMICE_GROUP_ID); }

void nw_animice_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = nw_animice_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (NWANIMICE_OBJFLAG_HIDDEN | NWANIMICE_OBJFLAG_HITDETECT_DISABLED));
    ObjGroup_AddObject((u32)obj, NW_ANIMICE_GROUP_ID);
}
