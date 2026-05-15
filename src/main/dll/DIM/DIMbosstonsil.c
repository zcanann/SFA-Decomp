#include "ghidra_import.h"
#include "main/dll/DIM/DIMbosstonsil.h"

extern void fn_8002B8C8(void *obj, int resourceId);
extern undefined4 ObjAnim_AdvanceCurrentMove(f32 moveStepScale, f32 deltaTime, int objAnimArg,
                                             void *eventList);
extern undefined4 ObjAnim_SetCurrentMove(int objAnimArg, int moveId, f32 moveProgress, int flags);
extern void objRenderFn_8003b8f4(int obj, undefined4 param_2, undefined4 param_3,
                                 undefined4 param_4, undefined4 param_5, double scale);
typedef undefined4 (*ObjAnimAdvanceObjectFirstFn)(int objAnimArg, double moveStepScale,
                                                  double deltaTime, void *eventList);

extern f32 timeDelta;
extern f32 lbl_803E4C80;
extern f32 lbl_803E4C84;
extern f32 lbl_803E4C88;

#pragma scheduling off
#pragma peephole off
int fn_801BDBE0(int p1, int p2, void *p3)
{
  *(s16 *)((char *)p3 + 0x6e) = -1;
  *(u8 *)((char *)p3 + 0x56) = 0;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

int dimbossgut_getExtraSize(void) { return 0x0; }
int dimbossgut_func08(void) { return 0x0; }
void dimbossgut_free(void) {}

#pragma scheduling off
#pragma peephole off
void DIMbossgut_render(int obj, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                       undefined4 param_5, char shouldRender)
{
  int visible;

  visible = shouldRender;
  if (visible != 0) {
    ObjAnim_AdvanceCurrentMove(lbl_803E4C80, timeDelta, obj, NULL);
    objRenderFn_8003b8f4(obj, param_2, param_3, param_4, param_5, (double)lbl_803E4C84);
  }
}
#pragma peephole reset
#pragma scheduling reset

void dimbossgut_hitDetect(void) {}
void dimbossgut_update(void) {}

#pragma scheduling off
#pragma peephole off
void DIMbossgut_init(void *obj)
{
  int objArg;

  fn_8002B8C8(obj, 0x5a);
  *(void **)((char *)obj + 0xbc) = fn_801BDBE0;
  objArg = (int)obj;
  ObjAnim_SetCurrentMove(objArg, 0, lbl_803E4C88, 0);
  ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
      (objArg, (double)lbl_803E4C80, (double)timeDelta, NULL);
}
#pragma peephole reset
#pragma scheduling reset

void dimbossgut_release(void) {}
void dimbossgut_initialise(void) {}
