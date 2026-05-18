#include "ghidra_import.h"
#include "main/dll/DIM/DIMbossgut.h"

extern void objSetSlot(void *obj, int resourceId);
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
int DIMbossgut_updateState(int obj, int param_2, void *state)
{
  *(s16 *)((char *)state + 0x6e) = -1;
  *(u8 *)((char *)state + 0x56) = 0;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

int DIMbossgut_getExtraSize(void) { return 0x0; }
int DIMbossgut_func08(void) { return 0x0; }
void DIMbossgut_free(void) {}

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

void DIMbossgut_hitDetect(void) {}
void DIMbossgut_update(void) {}

#pragma scheduling off
#pragma peephole off
void DIMbossgut_init(void *obj)
{
  int objArg;

  objSetSlot(obj, 0x5a);
  *(void **)((char *)obj + 0xbc) = DIMbossgut_updateState;
  objArg = (int)obj;
  ObjAnim_SetCurrentMove(objArg, 0, lbl_803E4C88, 0);
  ((ObjAnimAdvanceObjectFirstFn)ObjAnim_AdvanceCurrentMove)
      (objArg, (double)lbl_803E4C80, (double)timeDelta, NULL);
}
#pragma peephole reset
#pragma scheduling reset

void DIMbossgut_release(void) {}
void DIMbossgut_initialise(void) {}

ObjectDescriptor gDIM_BossGutObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DIMbossgut_initialise,
    (ObjectDescriptorCallback)DIMbossgut_release,
    0,
    (ObjectDescriptorCallback)DIMbossgut_init,
    (ObjectDescriptorCallback)DIMbossgut_update,
    (ObjectDescriptorCallback)DIMbossgut_hitDetect,
    (ObjectDescriptorCallback)DIMbossgut_render,
    (ObjectDescriptorCallback)DIMbossgut_free,
    (ObjectDescriptorCallback)DIMbossgut_func08,
    DIMbossgut_getExtraSize,
};
