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

extern void fn_801B9ECC(void);
extern void fn_801BA224(void);
extern void fn_801BA4B8(void);
extern void fn_801BA590(void);
extern void fn_801BA5A8(void);
extern void fn_801BA5F0(void);
extern void fn_801BA654(void);
extern void fn_801BA780(void);
extern void fn_801BA880(void);
extern void fn_801BA958(void);
extern void fn_801BAA84(void);
extern void fn_801BAB88(void);
extern void fn_801BACB8(void);
extern void fn_801BAE00(void);
extern void fn_801BAF58(void);
extern void fn_801BB0D8(void);
extern void fn_801BB1EC(void);
extern void fn_801BB2B0(void);

extern void (*lbl_803AD000[])(void);
extern void (*lbl_803AD018[])(void);

#pragma scheduling off
#pragma peephole off
void fn_801BDAF4(void)
{
  void (**table)(void);

  table = lbl_803AD018;
  table[0] = fn_801BB2B0;
  table[1] = fn_801BB1EC;
  table[2] = fn_801BB0D8;
  table[3] = fn_801BAF58;
  table[4] = fn_801BAE00;
  table[5] = fn_801BACB8;
  table[6] = fn_801BAB88;
  table[7] = fn_801BAA84;
  table[8] = fn_801BA958;
  table[9] = fn_801BA880;
  table[10] = fn_801BA780;
  table[11] = fn_801BA654;

  table = lbl_803AD000;
  table[0] = fn_801BA5F0;
  table[1] = fn_801BA5A8;
  table[2] = fn_801BA590;
  table[3] = fn_801BA4B8;
  table[4] = fn_801BA224;
  table[5] = fn_801B9ECC;
}
#pragma peephole reset
#pragma scheduling reset

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
