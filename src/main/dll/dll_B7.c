#include "ghidra_import.h"
#include "main/dll/dll_B7.h"

extern void Resource_Release(void *handle);
extern void *Resource_Acquire(int id, int mode);
extern void mm_free(void *ptr);
extern void *mmAlloc(int size, int heap, int flags);

extern void *lbl_803A4228[20];
extern void *pCamera;
extern void *lbl_803DD51C;
extern int lbl_803DD518;
extern int lbl_803DD514;
extern u8 lbl_803DD520;
extern s8 lbl_803DD500;
extern s8 lbl_803DD501;
extern int lbl_803DD508;
extern int lbl_803DD50C;

#pragma scheduling off
#pragma peephole off
void camcontrol_activateHandler(u32 actionId, void *actionData)
{
  void *entry;
  int idx;
  int n;
  int priority;

  if (lbl_803DD51C != NULL) {
    if (lbl_803DD518 != (int)(u16)actionId) {
      (*(void (****)(void *))((char *)lbl_803DD51C + 4))[0][3](pCamera);
      if (*(u8 *)((char *)lbl_803DD51C + 8) == 1) {
        idx = lbl_803DD514;
        Resource_Release(*(void **)((char *)lbl_803A4228[idx] + 4));
        mm_free(lbl_803A4228[idx]);
        lbl_803A4228[idx] = lbl_803A4228[lbl_803DD520 - 1];
        lbl_803DD520--;
        lbl_803DD51C = NULL;
        lbl_803DD518 = -1;
        lbl_803DD514 = -1;
      }
    }
  }

  idx = 0;
  n = lbl_803DD520;
  {
    void **p = lbl_803A4228;
    for (; idx < n; idx++) {
      if (*(u16 *)*p == (u16)actionId) goto found;
      p++;
    }
  }
  idx = -1;
found:
  lbl_803DD514 = idx;

  if (idx == -1) {
    void *new_entry;
    priority = lbl_803DD500;
    new_entry = mmAlloc(0xC, 0xF, 0);
    n = lbl_803DD520;
    lbl_803A4228[n] = new_entry;
    lbl_803DD520++;
    entry = lbl_803A4228[n];
    *(u16 *)entry = actionId;
    *((u8 *)entry + 8) = priority;
    *(void **)((u8 *)entry + 4) = Resource_Acquire(actionId, 4);
    lbl_803DD514 = lbl_803DD520 - 1;
  }

  if (lbl_803DD514 != -1) {
    entry = lbl_803A4228[lbl_803DD514];
    lbl_803DD51C = entry;
    lbl_803DD518 = *(u16 *)entry;
    (*(void (****)(void *, int, void *))((char *)entry + 4))[0][1](pCamera, lbl_803DD501, actionData);
  } else {
    lbl_803DD51C = NULL;
    lbl_803DD518 = -1;
  }

  lbl_803DD50C = lbl_803DD500;
  lbl_803DD508 = lbl_803DD501;
}
#pragma peephole reset
#pragma scheduling reset
