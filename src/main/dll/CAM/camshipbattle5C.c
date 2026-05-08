#include "ghidra_import.h"
#include "main/dll/CAM/camshipbattle5C.h"

extern undefined4 FUN_80135810();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e2520;
extern f32 lbl_803E2508;
extern f32 lbl_803E2510;
extern f32 lbl_803E2514;
extern f32 lbl_803E2518;
extern char sPathcamErrorNeedAtLeastTwoControlPoints[];

/*
 * --INFO--
 *
 * Function: pathcam_buildWindowSamples
 * EN v1.0 Address: 0x8010A590
 * EN v1.0 Size: 1236b
 * EN v1.1 Address: 0x8010A82C
 * EN v1.1 Size: 1220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void pathcam_buildWindowSamples(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,
                                float *param_5,float *param_6,float *param_7,float *param_8)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  double dVar6;
  float *pfVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  int *piVar12;
  float *pfVar13;
  float *pfVar14;
  float *pfVar15;
  int *piVar16;
  undefined4 *puVar17;
  int iVar18;
  undefined8 uVar19;
  int local_88 [4];
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  
  uVar19 = FUN_8028680c();
  pfVar9 = (float *)uVar19;
  iVar18 = 0;
  piVar12 = local_88;
  pfVar7 = param_8;
  pfVar10 = param_7;
  pfVar11 = param_6;
  pfVar13 = param_5;
  pfVar14 = param_4;
  pfVar15 = param_3;
  piVar16 = piVar12;
  do {
    puVar17 = (undefined4 *)((ulonglong)uVar19 >> 0x20);
    iVar8 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar17);
    *piVar16 = iVar8;
    iVar8 = *piVar16;
    if (iVar8 != 0) {
      *(undefined4 *)uVar19 = *(undefined4 *)(iVar8 + 8);
      *pfVar15 = *(float *)(iVar8 + 0xc);
      *pfVar14 = *(float *)(iVar8 + 0x10);
      dVar6 = DOUBLE_803e2520;
      uStack_74 = (int)*(short *)(iVar8 + 0x34) ^ 0x80000000;
      local_78 = 0x43300000;
      *pfVar13 = (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2520);
      uStack_6c = (int)*(short *)(iVar8 + 0x36) ^ 0x80000000;
      local_70 = 0x43300000;
      *pfVar11 = (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar6);
      uStack_64 = (int)*(short *)(iVar8 + 0x38) ^ 0x80000000;
      local_68 = 0x43300000;
      *pfVar10 = (float)((double)CONCAT44(0x43300000,uStack_64) - dVar6);
      uStack_5c = (int)*(char *)(iVar8 + 0x3a) ^ 0x80000000;
      local_60 = 0x43300000;
      *pfVar7 = (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar6);
    }
    piVar16 = piVar16 + 1;
    uVar19 = CONCAT44(puVar17 + 1,(undefined4 *)uVar19 + 1);
    pfVar15 = pfVar15 + 1;
    pfVar14 = pfVar14 + 1;
    pfVar13 = pfVar13 + 1;
    pfVar11 = pfVar11 + 1;
    pfVar10 = pfVar10 + 1;
    pfVar7 = pfVar7 + 1;
    iVar18 = iVar18 + 1;
  } while (iVar18 < 4);
  if ((local_88[1] != 0) && (local_88[2] != 0)) {
    iVar18 = 0;
    iVar8 = 4;
    pfVar7 = param_5;
    pfVar10 = param_6;
    pfVar11 = param_7;
    do {
      if (*piVar12 == 0) {
        if (iVar18 == 0) {
          *pfVar9 = *(float *)(local_88[1] + 8) +
                    (*(float *)(local_88[1] + 8) - *(float *)(local_88[2] + 8));
          *param_3 = *(float *)(local_88[1] + 0xc) +
                     (*(float *)(local_88[1] + 0xc) - *(float *)(local_88[2] + 0xc));
          *param_4 = *(float *)(local_88[1] + 0x10) +
                     (*(float *)(local_88[1] + 0x10) - *(float *)(local_88[2] + 0x10));
          dVar6 = DOUBLE_803e2520;
          uStack_5c = *(short *)(local_88[1] + 0x34) * 2 - (int)*(short *)(local_88[2] + 0x34) ^
                      0x80000000;
          local_60 = 0x43300000;
          *pfVar7 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2520);
          uStack_64 = *(short *)(local_88[1] + 0x36) * 2 - (int)*(short *)(local_88[2] + 0x36) ^
                      0x80000000;
          local_68 = 0x43300000;
          *pfVar10 = (float)((double)CONCAT44(0x43300000,uStack_64) - dVar6);
          uStack_6c = *(short *)(local_88[1] + 0x38) * 2 - (int)*(short *)(local_88[2] + 0x38) ^
                      0x80000000;
          local_70 = 0x43300000;
          *pfVar11 = (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar6);
          uStack_74 = (int)*(char *)(local_88[1] + 0x3a) ^ 0x80000000;
          local_78 = 0x43300000;
          uStack_54 = uStack_74;
          local_58 = 0x43300000;
          uStack_4c = (int)*(char *)(local_88[2] + 0x3a) ^ 0x80000000;
          local_50 = 0x43300000;
          *param_8 = (float)((double)CONCAT44(0x43300000,uStack_74) - dVar6) +
                     ((float)((double)CONCAT44(0x43300000,uStack_74) - dVar6) -
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - dVar6));
        }
        else if (iVar18 == 3) {
          *pfVar9 = *(float *)(local_88[2] + 8) +
                    (*(float *)(local_88[2] + 8) - *(float *)(local_88[1] + 8));
          *param_3 = *(float *)(local_88[2] + 0xc) +
                     (*(float *)(local_88[2] + 0xc) - *(float *)(local_88[1] + 0xc));
          *param_4 = *(float *)(local_88[2] + 0x10) +
                     (*(float *)(local_88[2] + 0x10) - *(float *)(local_88[1] + 0x10));
          dVar6 = DOUBLE_803e2520;
          uStack_4c = *(short *)(local_88[2] + 0x34) * 2 - (int)*(short *)(local_88[1] + 0x34) ^
                      0x80000000;
          local_50 = 0x43300000;
          *pfVar7 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2520);
          uStack_54 = *(short *)(local_88[2] + 0x36) * 2 - (int)*(short *)(local_88[1] + 0x36) ^
                      0x80000000;
          local_58 = 0x43300000;
          *pfVar10 = (float)((double)CONCAT44(0x43300000,uStack_54) - dVar6);
          uStack_5c = *(short *)(local_88[2] + 0x38) * 2 - (int)*(short *)(local_88[1] + 0x38) ^
                      0x80000000;
          local_60 = 0x43300000;
          *pfVar11 = (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar6);
          uStack_64 = (int)*(char *)(local_88[2] + 0x3a) ^ 0x80000000;
          local_68 = 0x43300000;
          uStack_6c = uStack_64;
          local_70 = 0x43300000;
          uStack_74 = (int)*(char *)(local_88[1] + 0x3a) ^ 0x80000000;
          local_78 = 0x43300000;
          *param_8 = (float)((double)CONCAT44(0x43300000,uStack_64) - dVar6) +
                     ((float)((double)CONCAT44(0x43300000,uStack_64) - dVar6) -
                     (float)((double)CONCAT44(0x43300000,uStack_74) - dVar6));
        }
      }
      piVar12 = piVar12 + 1;
      pfVar9 = pfVar9 + 1;
      param_3 = param_3 + 1;
      param_4 = param_4 + 1;
      pfVar7 = pfVar7 + 1;
      pfVar10 = pfVar10 + 1;
      pfVar11 = pfVar11 + 1;
      param_8 = param_8 + 1;
      iVar18 = iVar18 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    iVar18 = 0;
    do {
      fVar5 = lbl_803E2518;
      fVar4 = lbl_803E2514;
      fVar3 = lbl_803E2510;
      fVar2 = lbl_803E2508;
      pfVar7 = param_5;
      if ((iVar18 != 0) && (pfVar7 = param_7, iVar18 == 1)) {
        pfVar7 = param_6;
      }
      if (pfVar7 != (float *)0x0) {
        iVar8 = 3;
        do {
          fVar1 = *pfVar7 - pfVar7[1];
          if ((fVar3 < fVar1) || (fVar1 < fVar4)) {
            if (fVar2 <= *pfVar7) {
              if (pfVar7[1] < fVar2) {
                pfVar7[1] = pfVar7[1] + fVar5;
              }
            }
            else {
              *pfVar7 = *pfVar7 + fVar5;
            }
          }
          pfVar7 = pfVar7 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
      iVar18 = iVar18 + 1;
    } while (iVar18 < 3);
  }
  FUN_80286858();
  return;
}
#pragma peephole reset
#pragma scheduling reset

extern char sPathCamNeedTwoControlPointsError[];
extern void debugPrintf(const char *fmt, ...);
extern void *lbl_803DCA9C;

/*
 * --INFO--
 *
 * Function: pathcam_findTaggedNodeWindow
 * EN v1.0 Address: 0x8010AA54
 * EN v1.0 Size: 500b
 */
void pathcam_findTaggedNodeWindow(int node, int *out, u8 tag)
{
    int i;
    int *cur;
    int *p;

    out[0] = -1;
    out[1] = -1;
    out[2] = -1;
    out[3] = -1;

    if (node == 0) return;

    out[1] = *(int *)(node + 0x14);

    cur = (int *)node;
    for (i = 0; i < 5; i++) {
        int idx = *(int *)((u8 *)cur + 0x1c);
        if (idx > -1) {
            p = (int *)(**(int *(**)(int))(*(int *)lbl_803DCA9C + 0x1c))(idx);
            if (p != 0) {
                if (*(u8 *)((u8 *)p + 0x31) == tag ||
                    *(u8 *)((u8 *)p + 0x32) == tag ||
                    *(u8 *)((u8 *)p + 0x33) == tag) {
                    if ((s8)*(u8 *)(node + 0x1b) & (1 << i)) {
                        out[0] = *(int *)((u8 *)cur + 0x1c);
                    } else {
                        out[2] = *(int *)((u8 *)cur + 0x1c);
                    }
                }
            }
        }
        cur = (int *)((u8 *)cur + 4);
    }

    if (out[2] > -1) {
        p = (int *)(**(int *(**)(int))(*(int *)lbl_803DCA9C + 0x1c))(out[2]);
        if (p != 0) {
            if (*(u8 *)((u8 *)p + 0x31) == tag ||
                *(u8 *)((u8 *)p + 0x32) == tag ||
                *(u8 *)((u8 *)p + 0x33) == tag) {
                cur = (int *)node;
                for (i = 0; i < 5; i++) {
                    int idx = *(int *)((u8 *)cur + 0x1c);
                    if (idx > -1 && ((s8)*(u8 *)(node + 0x1b) & (1 << i)) == 0) {
                        int *p2 = (int *)(**(int *(**)(int))(*(int *)lbl_803DCA9C + 0x1c))(idx);
                        if (p2 != 0 && (
                            *(u8 *)((u8 *)p2 + 0x31) == tag ||
                            *(u8 *)((u8 *)p2 + 0x32) == tag ||
                            *(u8 *)((u8 *)p2 + 0x33) == tag)) {
                            out[3] = *(int *)((u8 *)cur + 0x1c);
                        }
                    }
                    cur = (int *)((u8 *)cur + 4);
                }
            }
        }
    }

    if (out[1] < 0 || out[2] < 0) {
        debugPrintf(sPathCamNeedTwoControlPointsError);
    }
}
