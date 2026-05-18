#include "ghidra_import.h"
#include "main/dll/dll_B7.h"

extern void Resource_Release(void *handle);
extern void *Resource_Acquire(int id, int mode);
extern void mm_free(void *ptr);
extern void *mmAlloc(int size, int heap, int flags);

extern void *gCamcontrolHandlerEntries[20];
extern void *pCamera;
extern void *gCamcontrolCurrentHandler;
extern int gCamcontrolActiveActionId;
extern int gCamcontrolCurrentHandlerIndex;
extern u8 gCamcontrolHandlerCount;
extern s8 gCamcontrolQueuedActionPriority;
extern s8 gCamcontrolQueuedActionStartFlags;
extern int gCamcontrolActiveActionStartFlags;
extern int gCamcontrolActiveActionPriority;

#pragma scheduling off
#pragma peephole off
void camcontrol_activateHandler(u32 actionId, void *actionData)
{
  void *entry;
  int idx;
  int n;
  int priority;

  if (gCamcontrolCurrentHandler != NULL) {
    if (gCamcontrolActiveActionId != (int)(u16)actionId) {
      (*(void (****)(void *))((char *)gCamcontrolCurrentHandler + 4))[0][3](pCamera);
      if (*(u8 *)((char *)gCamcontrolCurrentHandler + 8) == 1) {
        idx = gCamcontrolCurrentHandlerIndex;
        Resource_Release(*(void **)((char *)gCamcontrolHandlerEntries[idx] + 4));
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
    void **p = gCamcontrolHandlerEntries;
    n = gCamcontrolHandlerCount;
    for (; idx < n; idx++) {
      if ((u16)actionId != *(u16 *)*p) {
        p++;
      } else {
        goto found;
      }
    }
  }
  idx = -1;
found:
  gCamcontrolCurrentHandlerIndex = idx;

  if (idx == -1) {
    void *new_entry;
    priority = gCamcontrolQueuedActionPriority;
    new_entry = mmAlloc(0xC, 0xF, 0);
    n = gCamcontrolHandlerCount;
    gCamcontrolHandlerEntries[n] = new_entry;
    gCamcontrolHandlerCount++;
    entry = gCamcontrolHandlerEntries[n];
    *(u16 *)entry = actionId;
    *((u8 *)entry + 8) = priority;
    *(void **)((u8 *)entry + 4) = Resource_Acquire(actionId, 4);
    gCamcontrolCurrentHandlerIndex = gCamcontrolHandlerCount - 1;
  }

  if (gCamcontrolCurrentHandlerIndex != -1) {
    entry = gCamcontrolHandlerEntries[gCamcontrolCurrentHandlerIndex];
    gCamcontrolCurrentHandler = entry;
    gCamcontrolActiveActionId = *(u16 *)entry;
    (*(void (****)(void *, int, void *))((char *)entry + 4))[0][1](pCamera, gCamcontrolQueuedActionStartFlags, actionData);
  } else {
    gCamcontrolCurrentHandler = NULL;
    gCamcontrolActiveActionId = -1;
  }

  gCamcontrolActiveActionPriority = gCamcontrolQueuedActionPriority;
  gCamcontrolActiveActionStartFlags = gCamcontrolQueuedActionStartFlags;
}
#pragma peephole reset
#pragma scheduling reset
