#include "ghidra_import.h"
#include "main/dll/CAM/camcontrol.h"
#include "main/dll/dll_B7.h"

extern void Resource_Release(void *handle);
extern void *Resource_Acquire(int id, int mode);
extern void mm_free(void *ptr);
extern void *mmAlloc(int size, int heap, int flags);

#pragma scheduling off
#pragma peephole off
void camcontrol_activateHandler(u32 actionId, void *actionData)
{
  CamcontrolHandlerEntry *entry;
  int idx;
  int n;
  int priority;

  if (gCamcontrolCurrentHandler != NULL) {
    if (gCamcontrolActiveActionId != (int)(u16)actionId) {
      gCamcontrolCurrentHandler->handler->vtable->release(pCamera);
      if (gCamcontrolCurrentHandler->priority == 1) {
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

  idx = 0;
  {
    register CamcontrolHandlerEntry **p;
    asm {
      lis r3, gCamcontrolHandlerEntries@ha
      addi p, r3, gCamcontrolHandlerEntries@l
    }
    n = gCamcontrolHandlerCount;
    for (; idx < n; idx++) {
      if ((u16)actionId == (*p)->actionId) {
        goto found;
      }
      p++;
    }
  }
  idx = -1;
found:
  gCamcontrolCurrentHandlerIndex = idx;

  if (idx == -1) {
    CamcontrolHandlerEntry *new_entry;
    priority = gCamcontrolQueuedActionPriority;
    new_entry = mmAlloc(0xC, 0xF, 0);
    n = gCamcontrolHandlerCount;
    gCamcontrolHandlerEntries[n] = new_entry;
    gCamcontrolHandlerCount++;
    entry = gCamcontrolHandlerEntries[n];
    entry->actionId = actionId;
    entry->priority = priority;
    entry->handler = Resource_Acquire(actionId, 4);
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
#pragma peephole reset
#pragma scheduling reset
