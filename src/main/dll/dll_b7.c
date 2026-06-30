/*
 * Camera-control action handler dispatcher (DLL 0xB7, part of the CAM
 * camcontrol family rooted at dll_0001_camcontrol).
 *
 * camcontrol_activateHandler() switches the active camera "action" by id.
 * It maintains gCamcontrolHandlerEntries[], a pool of loaded action
 * handlers (each a Resource_Acquire'd CamcontrolHandler with a vtable).
 * On a change of action it releases the outgoing handler (and, if that
 * entry was dynamically priority-loaded, frees and swap-removes its pool
 * slot), looks up or lazily loads the handler for the requested action,
 * then activates it through its vtable with the queued start flags. The
 * queued action priority/start-flags are latched into the active slots.
 *
 * Driven by the queued-action state set up in the camcontrol update path
 * (see dll_bb.c's call site).
 */
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_B7.h"
#include "main/mm.h"

extern BOOL Resource_Release(void *handleSlot);
extern void *Resource_Acquire(u16 id, int unused);

static inline int camcontrol_findHandlerIndex(u16 actionId)
{
    int handlerCount;
    register CamcontrolHandlerEntry **handlerEntry;
    int handlerIndex;

    handlerIndex = 0;
    handlerEntry = gCamcontrolHandlerEntries;
    for (handlerCount = gCamcontrolHandlerCount; 0 < handlerCount; handlerCount--) {
        if (actionId == (*handlerEntry)->actionId) {
            return handlerIndex;
        }
        handlerEntry++;
        handlerIndex++;
    }
    return -1;
}

void camcontrol_activateHandler(u16 actionId, void *actionData)
{
    CamcontrolHandlerEntry *entry;
    int idx;
    int n;
    int priority;

    if (gCamcontrolCurrentHandler != NULL) {
        if (gCamcontrolActiveActionId != actionId) {
            gCamcontrolCurrentHandler->handler->vtable->release(pCamera);
            if (gCamcontrolCurrentHandler->priority == CAMCONTROL_HANDLER_PRIORITY_DYNAMIC) {
                idx = gCamcontrolCurrentHandlerIndex;
                Resource_Release(gCamcontrolHandlerEntries[idx]->handler);
                mm_free(gCamcontrolHandlerEntries[idx]);
                gCamcontrolHandlerEntries[idx] = gCamcontrolHandlerEntries[gCamcontrolHandlerCount - 1];
                gCamcontrolHandlerCount--;
                gCamcontrolCurrentHandler = NULL;
                gCamcontrolActiveActionId = -1;
                gCamcontrolCurrentHandlerIndex = -1;
            }
        }
    }

    idx = camcontrol_findHandlerIndex(actionId);
    gCamcontrolCurrentHandlerIndex = idx;

    if (idx == -1) {
        CamcontrolHandlerEntry *new_entry;
        priority = gCamcontrolQueuedActionPriority;
        new_entry = mmAlloc(CAMCONTROL_HANDLER_ENTRY_SIZE, CAMCONTROL_ACTION_HEAP, 0);
        n = gCamcontrolHandlerCount;
        gCamcontrolHandlerEntries[n] = new_entry;
        gCamcontrolHandlerCount++;
        entry = gCamcontrolHandlerEntries[n];
        entry->actionId = actionId;
        entry->priority = priority;
        entry->handler = Resource_Acquire(actionId, CAMCONTROL_HANDLER_RESOURCE_TYPE);
        gCamcontrolCurrentHandlerIndex = gCamcontrolHandlerCount - 1;
    }

    if (gCamcontrolCurrentHandlerIndex != -1) {
        entry = gCamcontrolHandlerEntries[gCamcontrolCurrentHandlerIndex];
        gCamcontrolCurrentHandler = entry;
        gCamcontrolActiveActionId = entry->actionId;
        entry->handler->vtable->activate(pCamera, gCamcontrolQueuedActionStartFlags, actionData);
    } else {
        gCamcontrolCurrentHandler = NULL;
        gCamcontrolActiveActionId = -1;
    }

    gCamcontrolActiveActionPriority = gCamcontrolQueuedActionPriority;
    gCamcontrolActiveActionStartFlags = gCamcontrolQueuedActionStartFlags;
}
