#ifndef MAIN_DLL_SC_SC_SHARED_H_
#define MAIN_DLL_SC_SC_SHARED_H_

#include "main/game_object.h"

/* Constants shared across the LightFoot Village (map "swapcircle") SC DLLs.
   The totem-pole tracking test, the totem-bond ceremony and the tug-of-war
   test of strength all scan for the same totem-pole peer objects and hand
   them events through the same object-DLL vtable slot. */

/* anim.seqId of the totem-pole objects (the Tracking Test poles); the
   totem-bond and strength controllers locate these peers by this id. */
#define SC_SEQ_TOTEMPOLE 0x282

/* anim.dll vtable slot taking an event id:
   (*obj->anim.dll)[SC_VT_HANDLE_EVENT](obj, eventId). */
#define SC_VT_HANDLE_EVENT 0x20

typedef struct SCTotemPoleInterfaceVTable
{
    void* pad00[8];
    void (*handleEvent)(GameObject* totemPole, int eventId);
} SCTotemPoleInterfaceVTable;

STATIC_ASSERT(offsetof(SCTotemPoleInterfaceVTable, handleEvent) == SC_VT_HANDLE_EVENT);

#endif /* MAIN_DLL_SC_SC_SHARED_H_ */
