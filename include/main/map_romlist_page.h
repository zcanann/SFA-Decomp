#ifndef MAIN_MAP_ROMLIST_PAGE_H_
#define MAIN_MAP_ROMLIST_PAGE_H_

#include "main/obj_placement.h"

typedef struct MapRomListPage
{
    u8 unk00[0x10];
    u8* loadedObjectBits;
    u8 unk14[0x0C];
    ObjPlacement* objects;
} MapRomListPage;

STATIC_ASSERT(offsetof(MapRomListPage, loadedObjectBits) == 0x10);
STATIC_ASSERT(offsetof(MapRomListPage, objects) == 0x20);
STATIC_ASSERT(sizeof(MapRomListPage) == 0x24);

#endif /* MAIN_MAP_ROMLIST_PAGE_H_ */
