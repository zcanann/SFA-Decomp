#include "ghidra_import.h"
#include "main/dll/baddie/chuka.h"

extern undefined4 FUN_80006b14();

extern undefined4* lbl_803DCA78;
extern f64 lbl_803E7088;
extern f32 lbl_803E7078;
extern f32 lbl_803E707C;
extern f32 lbl_803E7080;

/*
 * --INFO--
 *
 * Function: chuka_init
 * EN v1.0 Address: 0x8020637C
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x80206444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void chuka_init(undefined2 *param_1,int param_2)
{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = lbl_803E7080;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - lbl_803E7088) / lbl_803E707C;
  }
  *(undefined *)((int)piVar2 + 9) = *(undefined *)(param_2 + 0x19);
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = lbl_803E7078;
  if (*(char *)((int)piVar2 + 9) == '\0') {
    *(undefined *)((int)piVar2 + 10) = 1;
    piVar1 = (int *)FUN_80006b14(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(char *)((int)piVar2 + 0xd) = (char)*(undefined2 *)(param_2 + 0x1c);
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfpfloorbar_free
 * EN v1.0 Address: 0x80206480
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80206590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef void (*DfpFloorbarFreeFn)(void *obj);

#pragma scheduling off
#pragma peephole off
void dfpfloorbar_free(int *obj)
{
  int *extra;

  extra = (int *)obj[0x2e];
  ((DfpFloorbarFreeFn)(*(u32 *)(*lbl_803DCA78 + 0x18)))(obj);
  extra[2] = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */
int fn_80206474(void) { return 0; }

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */
int dfpfloorbar_func08(void) { return 0; }

/*
 * --INFO--
 *
 * Function: chuka_release
 * EN v1.0 Address: 0x8020646C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_release(void)
{
}

/*
 * --INFO--
 *
 * Function: chuka_initialise
 * EN v1.0 Address: 0x80206470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_getExtraSize
 * EN v1.0 Address: 0x8020647C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfpfloorbar_getExtraSize(void)
{
  return 0xc;
}

extern f32 lbl_803E6408;
extern void objRenderFn_8003b8f4(f32);

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */
#pragma peephole off
void dfpfloorbar_render(int p1, int p2, int p3, int p4, int p5, s8 p6)
{
    s32 t = p6;
    if (t != 0) {
        objRenderFn_8003b8f4(lbl_803E6408);
    }
}
#pragma peephole reset

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
#pragma scheduling off
#pragma peephole off
void dfpfloorbar_hitDetect(int *obj)
{
    int *x;
    int **b;
    s32 v;
    b = (int **)obj[0x2e];
    x = b[2];
    if (x == NULL) return;
    v = *(s16 *)((char *)x + 6) & 0x40;
    if (v == 0) return;
    b[2] = NULL;
}
#pragma peephole reset
#pragma scheduling reset
