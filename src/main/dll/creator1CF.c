#include "ghidra_import.h"
#include "main/dll/creator1CF.h"

extern void *Camera_GetCurrentViewSlot(void);
extern float sqrtf(float x);
extern int randomGetRange(int min, int max);
extern void voxmaps_worldToGrid(void *world, void *grid);
extern int voxmaps_traceLine(void *from, void *to, void *out, int param4, int param5);

extern undefined4 *gExpgfxInterface;
extern undefined4 *gModgfxInterface;
extern undefined4 *pDll_expgfx;
extern u8 framesThisStep;
extern f32 lbl_803E51C8;
extern f32 lbl_803E51CC;
extern f32 lbl_803E51D0;
extern f32 lbl_803E51D4;
extern f32 lbl_803E51D8;
extern f32 lbl_803E51DC;

/*
 * --INFO--
 *
 * Function: dll_19E_free
 * EN v1.0 Address: 0x801CCFB4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CCFE4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dll_19E_free(int param_1)
{
  (*(code *)(*(int *)gModgfxInterface + 0x18))(param_1);
  (*(code *)(*(int *)gExpgfxInterface + 0x18))(param_1);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dll_19E_render
 * EN v1.0 Address: 0x801CD008
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x801CD0F8
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_19E_render(int param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                 undefined4 param_5, char param_6)
{
  int state;
  void *camera;
  float dx, dy, dz;
  float dist;
  float invDist;
  float fac1x, fac1y, fac1z;
  float fac2x, fac2y, fac2z;
  float gridA[2];
  float gridB[2];
  void *traceOut;
  float midA[3];
  float midB[3];
  float vecBA[3];
  float gfxVec[3];
  int auStack_28[2];

  state = *(int *)(param_1 + 0xb8);
  if ((int)(signed char)param_6 == 0) {
    *(short *)(state + 4) = 0;
    *(char *)(state + 0xa) = 0;
    goto end;
  }
  if (*(char *)(state + 0xc) == '\0') goto end;
  *(char *)(state + 0xa) = 1;
  camera = Camera_GetCurrentViewSlot();
  dx = *(float *)((int)camera + 0xc) - *(float *)(param_1 + 0xc);
  dy = *(float *)((int)camera + 0x10) - *(float *)(param_1 + 0x10);
  dz = *(float *)((int)camera + 0x14) - *(float *)(param_1 + 0x14);
  dist = sqrtf(dx * dx + dy * dy + dz * dz);
  if (dist > lbl_803E51C8) {
    invDist = lbl_803E51CC / dist;
    dx = dx * invDist;
    dy = dy * invDist;
    dz = dz * invDist;
    fac1x = lbl_803E51D0 * dx;
    fac1y = lbl_803E51D0 * dy;
    fac1z = lbl_803E51D0 * dz;
    midA[0] = fac1x + *(float *)(param_1 + 0xc);
    midA[1] = fac1y + *(float *)(param_1 + 0x10);
    midA[2] = fac1z + *(float *)(param_1 + 0x14);
    fac2x = lbl_803E51D4 * dx;
    fac2y = lbl_803E51D4 * dy;
    fac2z = lbl_803E51D4 * dz;
    midB[0] = fac2x + *(float *)((int)camera + 0xc);
    midB[1] = fac2y + *(float *)((int)camera + 0x10);
    midB[2] = fac2z + *(float *)((int)camera + 0x14);
    voxmaps_worldToGrid(midA, gridA);
    voxmaps_worldToGrid(midB, gridB);
    if (voxmaps_traceLine(gridB, gridB, auStack_28, 0, 0) == 0) {
      *(char *)(state + 0xa) = 0;
      (**(code **)(*gExpgfxInterface + 0x14))(param_1);
    }
  }
  if (*(short *)(state + 4) > 0) {
    *(short *)(state + 4) = *(short *)(state + 4) - framesThisStep;
    goto end;
  }
  if (*(char *)(state + 0xa) != '\0') {
    gfxVec[0] = lbl_803E51D8;
    gfxVec[1] = lbl_803E51DC;
    gfxVec[2] = lbl_803E51D8;
    (**(code **)(*pDll_expgfx + 0x8))(param_1, 0x1f7, gfxVec, 0x12, 0xffffffff, 0);
  }
  *(short *)(state + 4) = (short)(randomGetRange(-10, 10) + 0x3c);
end:
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_hitDetect(void) {}
