#include "ghidra_import.h"
#include "main/dll/cannonball.h"

extern bool Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern double getXZDistance(float *a, float *b);
extern u32 randomGetRange(int min, int max);
extern void objAudioFn_800393f8(int obj, void *audio, int soundId, int volume, int param5, int param6);
extern void curveFn_800da23c();
extern void fn_800DA928(float *p, float v);
extern void fn_800DA980();
extern int fn_800DBCFC(float *pos, void *flag);
extern void fn_80139834();
extern void fn_80139A8C();
extern void trickyFn_8013b368(int obj1, int obj2, float arg);

extern undefined4 *lbl_803DCA9C;
extern f32 timeDelta;
extern f64 lbl_803E2460;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E241C;
extern f32 lbl_803E2420;
extern f32 lbl_803E2488;
extern f32 lbl_803E2508;
extern f32 lbl_803E250C;

/*
 * --INFO--
 *
 * Function: fn_80141290
 * EN v1.0 Address: 0x80141290
 * EN v1.0 Size: 1520b
 * EN v1.1 Address: 0x80141618
 * EN v1.1 Size: 1520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80141290(int param_1, int param_2)
{
  float fVar1;
  float fVar2;
  bool bVar5;
  int iVar3;
  float fVar4;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  float fVar11;
  double dVar12;
  double dVar13;
  double in_f31;
  int sfxState;
  int local_48[4];

  iVar6 = param_2;
  iVar3 = param_1;
  iVar8 = 0;
  if (*(char *)(iVar6 + 10) == '\0') {
    trickyFn_8013b368(iVar3, iVar6, lbl_803E2488);
    iVar8 = fn_800DBCFC((float *)(*(int *)(iVar6 + 0x700) + 8), (void *)0x0);
    iVar3 = fn_800DBCFC((float *)(iVar3 + 0x18), (void *)0x0);
    if (iVar3 == iVar8) {
      fVar11 = *(float *)(iVar6 + 0x700);
      (**(code **)(*lbl_803DCA9C + 0x54))(fVar11, 0);
      fVar2 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))();
      (**(code **)(*lbl_803DCA9C + 0x60))(fVar11, 0);
      fVar1 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))();
      dVar13 = getXZDistance((float *)(*(int *)(iVar6 + 4) + 0x18), (float *)((int)fVar2 + 8));
      dVar12 = getXZDistance((float *)(*(int *)(iVar6 + 4) + 0x18), (float *)((int)fVar1 + 8));
      if (dVar13 <= dVar12) {
        (**(code **)(*lbl_803DCA9C + 0x60))(fVar1, 0);
        fVar4 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))();
        *(undefined4 *)(iVar6 + 0x4a0) = 1;
      }
      else {
        (**(code **)(*lbl_803DCA9C + 0x54))(fVar2, 0);
        fVar4 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))();
        *(undefined4 *)(iVar6 + 0x4a0) = 0;
        fVar1 = fVar2;
      }
      fn_800DA980(iVar6 + 0x420, fVar11, fVar1, fVar4);
      if (*(int *)(iVar6 + 0x4a0) == 0) {
        fn_800DA928((float *)(iVar6 + 0x420), lbl_803E23E0);
      }
      else {
        fn_800DA928((float *)(iVar6 + 0x420), lbl_803E250C);
      }
      *(float *)(iVar6 + 0x708) = lbl_803E23DC;
      *(undefined *)(iVar6 + 10) = 1;
    }
  }
  else {
    if (*(int *)(iVar6 + 0x4a0) == 0) {
      if (*(int *)(iVar6 + 0x430) != 0) {
        param_1 = *(int *)(iVar6 + 0x4c4);
        if ((-1 < *(int *)(param_1 + 0x1c)) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) {
          iVar8 = 1;
          local_48[0] = *(int *)(param_1 + 0x1c);
        }
        iVar9 = iVar8;
        if ((-1 < *(int *)(param_1 + 0x20)) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) {
          iVar9 = iVar8 + 1;
          local_48[iVar8] = *(int *)(param_1 + 0x20);
        }
        iVar8 = iVar9;
        if ((-1 < *(int *)(param_1 + 0x24)) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) {
          iVar8 = iVar9 + 1;
          local_48[iVar9] = *(int *)(param_1 + 0x24);
        }
        if ((-1 < *(int *)(param_1 + 0x28)) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) {
          local_48[iVar8] = *(int *)(param_1 + 0x28);
          iVar8 = iVar8 + 1;
        }
      }
    }
    else if (*(int *)(iVar6 + 0x430) == 0) {
      param_1 = *(int *)(iVar6 + 0x4c4);
      if ((-1 < *(int *)(param_1 + 0x1c)) && ((*(byte *)(param_1 + 0x1b) & 1) != 0)) {
        iVar8 = 1;
        local_48[0] = *(int *)(param_1 + 0x1c);
      }
      iVar9 = iVar8;
      if ((-1 < *(int *)(param_1 + 0x20)) && ((*(byte *)(param_1 + 0x1b) & 2) != 0)) {
        iVar9 = iVar8 + 1;
        local_48[iVar8] = *(int *)(param_1 + 0x20);
      }
      iVar10 = iVar9;
      if ((-1 < *(int *)(param_1 + 0x24)) && ((*(byte *)(param_1 + 0x1b) & 4) != 0)) {
        iVar10 = iVar9 + 1;
        local_48[iVar9] = *(int *)(param_1 + 0x24);
      }
      iVar8 = iVar10;
      if ((-1 < *(int *)(param_1 + 0x28)) && ((*(byte *)(param_1 + 0x1b) & 8) != 0)) {
        iVar8 = iVar10 + 1;
        local_48[iVar10] = *(int *)(param_1 + 0x28);
      }
    }
    if (iVar8 != 0) {
      fVar1 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))(local_48[0]);
      dVar12 = getXZDistance((float *)(*(int *)(iVar6 + 0x24) + 0x18), (float *)((int)fVar1 + 8));
      piVar7 = local_48;
      dVar13 = dVar12;
      for (iVar9 = 1; piVar7 = piVar7 + 1, iVar9 < iVar8; iVar9 = iVar9 + 1) {
        fVar2 = (float)(**(code **)(*lbl_803DCA9C + 0x1c))(*piVar7);
        dVar12 = getXZDistance((float *)(*(int *)(iVar6 + 0x24) + 0x18), (float *)((int)fVar2 + 8));
        if (dVar12 < dVar13) {
          fVar1 = fVar2;
          dVar13 = dVar12;
        }
      }
      curveFn_800da23c(iVar6 + 0x420, fVar1);
    }
    fVar1 = *(float *)(iVar6 + 0x14);
    if (fVar1 <= lbl_803E2508) {
      fVar1 = lbl_803E2420 * timeDelta + fVar1;
      if (lbl_803E2508 < fVar1) {
        fVar1 = lbl_803E2508;
      }
    }
    else {
      fVar1 = lbl_803E241C * timeDelta + fVar1;
      if (fVar1 < lbl_803E2508) {
        fVar1 = lbl_803E2508;
      }
    }
    *(float *)(iVar6 + 0x14) = fVar1;
    fn_80139834(iVar3, iVar6 + 0x420, (double)*(float *)(iVar6 + 0x14));
    fn_80139A8C(iVar3, iVar6 + 0x488);
    iVar8 = fn_800DBCFC((float *)(iVar3 + 0x18), (void *)0x0);
    if (iVar8 == 0) {
      *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x10;
    }
    else {
      *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) & 0xffffffef;
    }
    *(float *)(iVar6 + 0x708) = *(float *)(iVar6 + 0x708) - timeDelta;
    if (*(float *)(iVar6 + 0x708) < lbl_803E23DC) {
      local_48[1] = randomGetRange(200, 600);
      local_48[1] = local_48[1] ^ 0x80000000;
      local_48[0] = 0x43300000;
      *(float *)(iVar6 + 0x708) =
           (float)((double)CONCAT44(0x43300000, local_48[1]) - lbl_803E2460);
      sfxState = *(int *)(iVar3 + 0xb8);
      if (((*(byte *)(sfxState + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar3 + 0xa0) || (*(short *)(iVar3 + 0xa0) < 0x29)) &&
          (bVar5 = Sfx_IsPlayingFromObjectChannel(iVar3, 0x10), !bVar5)))) {
        objAudioFn_800393f8(iVar3, (void *)(sfxState + 0x3a8), 0x29b, 0x1000, 0xffffffff, 0);
      }
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_8014187C(void) {}
