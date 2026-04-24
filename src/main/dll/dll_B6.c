#include "ghidra_import.h"
#include "main/dll/dll_B6.h"

extern undefined4 FUN_800128fc();
extern undefined8 FUN_80012d20();
extern int FUN_8002bac4();
extern int FUN_8002e1f4();
extern undefined4 FUN_80286830();
extern undefined4 FUN_8028687c();
extern uint FUN_80296384();
extern int FUN_80296a88();

extern undefined4 gCamcontrolTargetTypeMask;
extern undefined4 gCamcontrolCurrentActionId;
extern f64 DOUBLE_803e22d0;
extern f32 FLOAT_803e22b0;
extern f32 FLOAT_803e22c4;
extern f32 FLOAT_803e22c8;

/*
 * --INFO--
 *
 * Function: camcontrol_findBestTarget
 * EN v1.0 Address: 0x801010B4
 * EN v1.0 Size: 1344b
 * EN v1.1 Address: 0x80101350
 * EN v1.1 Size: 1268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_findBestTarget(undefined8 param_1,double param_2,undefined8 param_3,
                               undefined8 param_4,undefined8 param_5,undefined8 param_6,
                               undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int extraout_r4;
  uint uVar5;
  undefined4 *puVar6;
  int iVar7;
  float *pfVar8;
  undefined4 *puVar9;
  float *pfVar10;
  int iVar11;
  int iVar12;
  float fVar13;
  uint uVar14;
  float *pfVar15;
  uint uVar16;
  undefined8 uVar17;
  double in_f31;
  double dVar18;
  double in_ps31_1;
  undefined local_c8 [4];
  int local_c4;
  int local_c0;
  undefined4 auStack_bc [3];
  short asStack_b0 [6];
  short local_a4 [6];
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  float local_8c;
  float local_88;
  undefined4 local_84;
  undefined4 local_80 [8];
  float local_60 [8];
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_80286830();
  uVar14 = 0xffffffff;
  iVar12 = 0;
  iVar11 = 0;
  iVar3 = FUN_8002bac4();
  if ((((iVar3 != 0) && (extraout_r4 != 0)) && (gCamcontrolCurrentActionId != 0x44)) &&
     (iVar4 = FUN_80296a88(iVar3), iVar4 != 0)) {
    iVar4 = FUN_8002e1f4(&local_c0,&local_c4);
    pfVar15 = (float *)(iVar4 + local_c0 * 4);
    for (; local_c0 < local_c4; local_c0 = local_c0 + 1) {
      fVar13 = *pfVar15;
      iVar4 = *(int *)((int)fVar13 + 0x78);
      if ((((iVar4 == 0) || (*(char *)((int)fVar13 + 0x36) != -1)) ||
          (((*(byte *)((int)fVar13 + 0xaf) & 0x28) != 0 ||
           (((*(ushort *)((int)fVar13 + 0xb0) & 0x800) == 0 &&
            ((*(uint *)(*(int *)((int)fVar13 + 0x50) + 0x44) & 1) == 0)))))) ||
         (((*(ushort *)((int)fVar13 + 6) & 0x4000) != 0 ||
          (((*(ushort *)((int)fVar13 + 0xb0) & 0x40) != 0 ||
           (bVar2 = true,
           ((uint)gCamcontrolTargetTypeMask &
           1 << (*(byte *)(iVar4 + (uint)*(byte *)((int)fVar13 + 0xe4) * 5 + 4) & 0xf)) == 0)))))) {
        bVar2 = false;
      }
      if (bVar2) {
        uVar5 = (uint)*(byte *)((int)fVar13 + 0xe4);
        iVar7 = uVar5 * 0x18;
        if ((int)uVar14 <=
            (int)(uint)*(byte *)(*(int *)(*(int *)((int)fVar13 + 0x50) + 0x40) + iVar7 + 0x11)) {
          fVar1 = FLOAT_803e22b0;
          if (((*(byte *)((int)fVar13 + 0xaf) & 0x80) == 0) &&
             ((*(byte *)(iVar4 + uVar5 * 5 + 4) & 0x80) == 0)) {
            fVar1 = *(float *)(extraout_r4 + 0x1c) -
                    *(float *)(*(int *)((int)fVar13 + 0x74) + iVar7 + 0x10);
          }
          if ((FLOAT_803e22c4 < fVar1) && (fVar1 < FLOAT_803e22c8)) {
            iVar7 = *(int *)((int)fVar13 + 0x74) + iVar7;
            param_2 = (double)(*(float *)(extraout_r4 + 0x18) - *(float *)(iVar7 + 0xc));
            fVar1 = *(float *)(extraout_r4 + 0x20) - *(float *)(iVar7 + 0x14);
            dVar18 = (double)(float)(param_2 * param_2 + (double)(fVar1 * fVar1));
            iVar4 = iVar4 + uVar5 * 5;
            uStack_3c = (uint)*(byte *)(iVar4 + 2) << 2 ^ 0x80000000;
            local_40 = 0x43300000;
            fVar1 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e22d0);
            if (dVar18 < (double)(fVar1 * fVar1)) {
              bVar2 = true;
              if (((*(byte *)(iVar4 + 4) & 0xf) == 2) && (uVar5 = FUN_80296384(iVar3), uVar5 != 0))
              {
                bVar2 = false;
              }
              if (bVar2) {
                uVar14 = (uint)*(byte *)(*(int *)(*(int *)((int)fVar13 + 0x50) + 0x40) +
                                        (uint)*(byte *)((int)fVar13 + 0xe4) * 0x18 + 0x11);
                iVar4 = 0;
                pfVar8 = local_60;
                while ((iVar4 < iVar12 &&
                       (uVar14 < *(byte *)(*(int *)(*(int *)((int)*pfVar8 + 0x50) + 0x40) +
                                          (uint)*(byte *)((int)*pfVar8 + 0xe4) * 0x18 + 0x11)))) {
                  pfVar8 = pfVar8 + 1;
                  iVar4 = iVar4 + 1;
                }
                pfVar8 = local_60 + iVar4 + -8;
                pfVar10 = local_60 + iVar4;
                while (((iVar4 < iVar12 && ((double)*pfVar8 < dVar18)) &&
                       (uVar14 == *(byte *)(*(int *)(*(int *)((int)*pfVar10 + 0x50) + 0x40) +
                                           (uint)*(byte *)((int)*pfVar10 + 0xe4) * 0x18 + 0x11)))) {
                  pfVar8 = pfVar8 + 1;
                  pfVar10 = pfVar10 + 1;
                  iVar4 = iVar4 + 1;
                }
                puVar6 = (undefined4 *)((int)local_80 + iVar11);
                puVar9 = (undefined4 *)((int)local_60 + iVar11);
                uVar5 = iVar12 - iVar4;
                if (iVar4 < iVar12) {
                  uVar16 = uVar5 >> 3;
                  if (uVar16 != 0) {
                    do {
                      *puVar6 = puVar6[-1];
                      *puVar9 = puVar9[-1];
                      puVar6[-1] = puVar6[-2];
                      puVar9[-1] = puVar9[-2];
                      puVar6[-2] = puVar6[-3];
                      puVar9[-2] = puVar9[-3];
                      puVar6[-3] = puVar6[-4];
                      puVar9[-3] = puVar9[-4];
                      puVar6[-4] = puVar6[-5];
                      puVar9[-4] = puVar9[-5];
                      puVar6[-5] = puVar6[-6];
                      puVar9[-5] = puVar9[-6];
                      puVar6[-6] = puVar6[-7];
                      puVar9[-6] = puVar9[-7];
                      puVar6[-7] = puVar6[-8];
                      puVar9[-7] = puVar9[-8];
                      puVar6 = puVar6 + -8;
                      puVar9 = puVar9 + -8;
                      uVar16 = uVar16 - 1;
                    } while (uVar16 != 0);
                    uVar5 = uVar5 & 7;
                    if (uVar5 == 0) goto LAB_80101720;
                  }
                  do {
                    *puVar6 = puVar6[-1];
                    *puVar9 = puVar9[-1];
                    puVar6 = puVar6 + -1;
                    puVar9 = puVar9 + -1;
                    uVar5 = uVar5 - 1;
                  } while (uVar5 != 0);
                }
LAB_80101720:
                local_60[iVar4 + -8] = (float)dVar18;
                local_60[iVar4] = fVar13;
                iVar12 = iVar12 + 1;
                iVar11 = iVar11 + 4;
                if (iVar12 == 8) break;
              }
            }
          }
        }
      }
      pfVar15 = pfVar15 + 1;
    }
    if ((0 < iVar12) &&
       (iVar3 = (uint)*(byte *)((int)local_60[0] + 0xe4) * 0x18,
       (*(byte *)(*(int *)(*(int *)((int)local_60[0] + 0x50) + 0x40) + iVar3 + 0x10) & 0x20) != 0))
    {
      local_8c = *(float *)(extraout_r4 + 0x18);
      local_88 = FLOAT_803e22c8 + *(float *)(extraout_r4 + 0x1c);
      local_84 = *(undefined4 *)(extraout_r4 + 0x20);
      local_98 = *(float *)(*(int *)((int)local_60[0] + 0x74) + iVar3);
      iVar3 = *(int *)((int)local_60[0] + 0x74) + iVar3;
      local_94 = *(undefined4 *)(iVar3 + 4);
      local_90 = *(undefined4 *)(iVar3 + 8);
      FUN_80012d20(&local_8c,local_a4);
      uVar17 = FUN_80012d20(&local_98,asStack_b0);
      FUN_800128fc(uVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_a4,
                   asStack_b0,auStack_bc,local_c8,0);
    }
  }
  FUN_8028687c();
  return;
}
