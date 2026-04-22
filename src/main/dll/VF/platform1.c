#include "ghidra_import.h"
#include "main/dll/VF/platform1.h"

extern undefined4 FUN_8000b9bc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern double FUN_80014648();
extern byte FUN_8001469c();
extern uint FUN_80014e40();
extern uint FUN_80022264();
extern uint FUN_8002bac4();
extern int FUN_8002e1f4();
extern int FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80088554();
extern undefined4 FUN_8011f670();
extern undefined4 FUN_8011f6d0();
extern undefined4 FUN_801de910();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4 DAT_803de890;
extern f64 DOUBLE_803e6340;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6300;
extern f32 FLOAT_803e6304;
extern f32 FLOAT_803e6308;
extern f32 FLOAT_803e630c;
extern f32 FLOAT_803e6310;
extern f32 FLOAT_803e6314;
extern f32 FLOAT_803e6318;
extern f32 FLOAT_803e631c;
extern f32 FLOAT_803e6320;
extern f32 FLOAT_803e6324;
extern f32 FLOAT_803e6328;
extern f32 FLOAT_803e632c;
extern f32 FLOAT_803e6330;
extern f32 FLOAT_803e6334;
extern f32 FLOAT_803e6338;
extern f32 FLOAT_803e633c;

/*
 * --INFO--
 *
 * Function: FUN_801dea20
 * EN v1.0 Address: 0x801DEA20
 * EN v1.0 Size: 2596b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dea20(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,int *param_13,
                 undefined4 param_14,undefined4 param_15,int param_16)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  byte bVar7;
  int iVar5;
  uint uVar6;
  uint *puVar8;
  int *piVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double in_f19;
  double in_f20;
  double in_f21;
  double in_f22;
  double dVar13;
  double in_f23;
  double dVar14;
  double in_f24;
  double dVar15;
  double in_f25;
  double dVar16;
  double in_f26;
  double dVar17;
  double in_f27;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps19_1;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_128;
  int local_124;
  int local_120;
  int local_11c;
  int *local_118;
  int local_114;
  int *local_110;
  int local_10c;
  int local_108;
  int local_104 [2];
  undefined local_fc;
  undefined4 local_f8;
  uint uStack_f4;
  undefined8 local_f0;
  float local_c8;
  float fStack_c4;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  local_c8 = (float)in_f19;
  fStack_c4 = (float)in_ps19_1;
  uVar2 = FUN_80286840();
  piVar9 = *(int **)(uVar2 + 0xb8);
  uVar3 = FUN_8002bac4();
  *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) | 4;
  FUN_8011f6d0(0xf);
  DAT_803de890 = 0;
  *piVar9 = 0;
  iVar4 = FUN_8002e1f4(local_104,&local_108);
  while (local_104[0] < local_108) {
    *piVar9 = *(int *)(iVar4 + local_104[0] * 4);
    local_104[0] = local_104[0] + 1;
    if (*(short *)(*piVar9 + 0x46) == 0x3ff) {
      local_104[0] = local_108;
    }
  }
  for (iVar4 = 0; fVar1 = FLOAT_803e6300, iVar4 < (int)(uint)*(byte *)(param_11 + 0x8b);
      iVar4 = iVar4 + 1) {
    bVar7 = *(byte *)(param_11 + iVar4 + 0x81);
    if (bVar7 == 3) {
      iVar5 = FUN_8002e1f4(&local_110,&local_10c);
      puVar8 = (uint *)(iVar5 + (int)local_110 * 4);
      for (; param_12 = local_10c, param_13 = local_110, (int)local_110 < local_10c;
          local_110 = (int *)((int)local_110 + 1)) {
        if ((*puVar8 != uVar2) && (*(short *)(*puVar8 + 0x46) == 0x282)) {
          iVar5 = *(int *)(iVar5 + (int)local_110 * 4);
          (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,2);
          break;
        }
        puVar8 = puVar8 + 1;
      }
    }
    else if (bVar7 < 3) {
      if (bVar7 == 1) {
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) | 1;
      }
      else if (bVar7 != 0) {
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) | 2;
        *(undefined2 *)((int)piVar9 + 0x2e) = 0;
        param_12 = 0;
        param_13 = (int *)*DAT_803dd6d4;
        (*(code *)param_13[0x14])(0x48,3,0);
      }
    }
    else if (bVar7 == 5) {
      if (*piVar9 != 0) {
        *(float *)(uVar3 + 0x98) = FLOAT_803e6300;
        *(float *)(*piVar9 + 0x98) = fVar1;
        FUN_8003042c((double)*(float *)(uVar3 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,uVar3,0x401,0,param_12,param_13,param_14,param_15,param_16);
        FUN_8003042c((double)*(float *)(*piVar9 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,*piVar9,0,0,param_12,param_13,param_14,param_15,param_16);
        piVar9[10] = piVar9[8];
      }
    }
    else if (bVar7 < 5) {
      iVar5 = FUN_8002e1f4(&local_118,&local_114);
      puVar8 = (uint *)(iVar5 + (int)local_118 * 4);
      for (; param_12 = local_114, param_13 = local_118, (int)local_118 < local_114;
          local_118 = (int *)((int)local_118 + 1)) {
        if ((*puVar8 != uVar2) && (*(short *)(*puVar8 + 0x46) == 0x282)) {
          iVar5 = *(int *)(iVar5 + (int)local_118 * 4);
          (**(code **)(**(int **)(iVar5 + 0x68) + 0x20))(iVar5,3);
          break;
        }
        puVar8 = puVar8 + 1;
      }
    }
  }
  if (((*(byte *)(piVar9 + 0xc) & 3) != 0) && (0x18 < piVar9[9])) {
    iVar4 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar4 != 0x48) {
      local_104[1] = 3;
      local_fc = 1;
      param_12 = 8;
      param_13 = local_104 + 1;
      param_14 = 0;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x48,1,3);
    }
    if (*(short *)(uVar3 + 0xa0) != 0x401) {
      FUN_8003042c((double)*(float *)(uVar3 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,uVar3,0x401,0,param_12,param_13,param_14,param_15,param_16);
    }
    iVar4 = *piVar9;
    if (*(short *)(iVar4 + 0xa0) != 0) {
      FUN_8003042c((double)*(float *)(iVar4 + 0x98),param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,iVar4,0,0,param_12,param_13,param_14,param_15,param_16);
    }
    *(undefined2 *)(param_11 + 0x6e) = 0xffff;
    *(undefined *)(param_11 + 0x56) = 0;
    FUN_8000da78(uVar2,0x3af);
    dVar13 = (double)FLOAT_803e6304;
    dVar14 = (double)FLOAT_803e630c;
    dVar15 = (double)FLOAT_803e6308;
    dVar16 = (double)FLOAT_803e6310;
    dVar17 = (double)FLOAT_803e631c;
    dVar18 = (double)FLOAT_803e6318;
    dVar19 = (double)FLOAT_803e6314;
    dVar20 = (double)FLOAT_803e6324;
    dVar21 = (double)FLOAT_803e6328;
    dVar22 = (double)FLOAT_803e6334;
    dVar12 = DOUBLE_803e6340;
    for (iVar4 = 0; iVar4 < (int)(uint)DAT_803dc070; iVar4 = iVar4 + 1) {
      if (*piVar9 == 0) goto LAB_801df3c4;
      uStack_f4 = piVar9[8] + 0xb24U ^ 0x80000000;
      local_f8 = 0x43300000;
      dVar10 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_f4) - dVar12) /
                              dVar13);
      dVar11 = (double)(float)(dVar14 * dVar10 + dVar15);
      if (dVar11 < dVar16) {
        dVar11 = -dVar11;
      }
      dVar10 = (double)(float)((double)(float)(dVar17 * dVar10 + dVar18) * dVar11 + dVar19);
      uVar6 = FUN_80014e40(0);
      if (((uVar6 & 0x100) != 0) && (bVar7 = FUN_8001469c(), bVar7 == 0)) {
        piVar9[2] = (int)((float)piVar9[2] - FLOAT_803e6320);
      }
      if ((double)(float)piVar9[2] < dVar20) {
        piVar9[2] = (int)(float)dVar20;
      }
      uVar6 = piVar9[8];
      if ((-0x46dd < (int)uVar6) && ((int)uVar6 < -0xb23)) {
        piVar9[8] = (int)((float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e6340)
                         + (float)piVar9[2]);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar9[10] ^ 0x80000000);
      uVar6 = piVar9[8];
      uStack_f4 = uVar6 ^ 0x80000000;
      local_f8 = 0x43300000;
      in_f19 = (double)(float)((double)((float)(local_f0 - dVar12) -
                                       (float)((double)CONCAT44(0x43300000,uStack_f4) - dVar12)) /
                              dVar21);
      if ((int)uVar6 < -0x46dc) {
        *(undefined2 *)((int)piVar9 + 0x2e) = 0;
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) & 0xfc;
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) | 8;
        iVar4 = FUN_8002e1f4(&local_120,&local_11c);
        puVar8 = (uint *)(iVar4 + local_120 * 4);
        goto LAB_801defcc;
      }
      if (-0xb24 < (int)uVar6) {
        *(undefined2 *)((int)piVar9 + 0x2e) = 3;
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) & 0xfc;
        *(byte *)(piVar9 + 0xc) = *(byte *)(piVar9 + 0xc) | 0x10;
        iVar4 = FUN_8002e1f4(&local_128,&local_124);
        puVar8 = (uint *)(iVar4 + local_128 * 4);
        goto LAB_801df0d8;
      }
      if (0 < piVar9[9]) {
        (**(code **)(*DAT_803dd6d4 + 0x74))();
      }
      if ((double)(float)piVar9[2] < dVar21) {
        piVar9[2] = (int)(float)((double)FLOAT_803e6330 * dVar10 + (double)(float)piVar9[2]);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar9[10] ^ 0x80000000);
      uStack_f4 = piVar9[8] ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar5 = FUN_8002fb40((double)(float)((double)((float)(local_f0 - dVar12) -
                                                   (float)((double)CONCAT44(0x43300000,uStack_f4) -
                                                          dVar12)) / dVar22),(double)FLOAT_803dc074)
      ;
      if ((iVar5 != 0) && (*(float *)(uVar3 + 0x98) < FLOAT_803e6310)) {
        *(float *)(uVar3 + 0x98) = FLOAT_803e6314 + *(float *)(uVar3 + 0x98);
      }
      local_f0 = (double)CONCAT44(0x43300000,piVar9[8] ^ 0x80000000);
      uStack_f4 = piVar9[10] ^ 0x80000000;
      local_f8 = 0x43300000;
      iVar5 = FUN_8002fb40((double)(float)((double)((float)(local_f0 - dVar12) -
                                                   (float)((double)CONCAT44(0x43300000,uStack_f4) -
                                                          dVar12)) / dVar22),(double)FLOAT_803dc074)
      ;
      if (iVar5 != 0) {
        fVar1 = *(float *)(*piVar9 + 0x98);
        if (fVar1 < FLOAT_803e6310) {
          *(float *)(*piVar9 + 0x98) = FLOAT_803e6314 + fVar1;
        }
      }
      piVar9[10] = piVar9[8];
    }
    piVar9[6] = (int)((float)piVar9[6] - FLOAT_803dc074);
    if ((double)(float)piVar9[6] < (double)FLOAT_803e6310) {
      if ((double)FLOAT_803e6310 <= in_f19) {
        uVar6 = FUN_80022264(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        piVar9[6] = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      else {
        uVar6 = FUN_80022264(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        piVar9[6] = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      FUN_8000bb38(uVar3,0x13a);
    }
    piVar9[7] = (int)((float)piVar9[7] - FLOAT_803dc074);
    if ((double)(float)piVar9[7] < (double)FLOAT_803e6310) {
      if (in_f19 <= (double)FLOAT_803e6310) {
        uVar3 = FUN_80022264(0x78,0xf0);
        local_f0 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        piVar9[7] = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      else {
        uVar3 = FUN_80022264(0x28,100);
        local_f0 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        piVar9[7] = (int)(float)(local_f0 - DOUBLE_803e6340);
      }
      FUN_8000bb38(uVar2,0x4a3);
    }
    if (in_f19 < (double)FLOAT_803e6310) {
      in_f19 = -in_f19;
    }
    iVar4 = (int)((double)FLOAT_803e6338 * in_f19);
    local_f0 = (double)(longlong)iVar4;
    if (100 < iVar4) {
      iVar4 = 100;
    }
    FUN_8000b9bc((double)FLOAT_803e633c,uVar2,0x3af,(byte)iVar4);
  }
LAB_801df3c4:
  FUN_8028688c();
  return;
LAB_801defcc:
  if (local_11c <= local_120) goto LAB_801defd8;
  if ((*puVar8 != uVar2) && (*(short *)(*puVar8 + 0x46) == 0x282)) {
    iVar4 = *(int *)(iVar4 + local_120 * 4);
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,4);
    goto LAB_801defd8;
  }
  puVar8 = puVar8 + 1;
  local_120 = local_120 + 1;
  goto LAB_801defcc;
LAB_801defd8:
  dVar12 = FUN_80014648();
  local_f0 = (double)(longlong)(int)(dVar12 / (double)FLOAT_803e632c);
  FUN_801de910();
  FUN_8011f670(0);
  if (0 < piVar9[9]) {
    FUN_80088554(piVar9[9]);
  }
  (**(code **)(*DAT_803dd6cc + 0xc))(0x14,1);
  DAT_803de890 = 2;
  goto LAB_801df3c4;
LAB_801df0d8:
  if (local_124 <= local_128) goto LAB_801df0e4;
  if ((*puVar8 != uVar2) && (*(short *)(*puVar8 + 0x46) == 0x282)) {
    iVar4 = *(int *)(iVar4 + local_128 * 4);
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x20))(iVar4,4);
    goto LAB_801df0e4;
  }
  puVar8 = puVar8 + 1;
  local_128 = local_128 + 1;
  goto LAB_801df0d8;
LAB_801df0e4:
  FUN_8011f670(0);
  if (0 < piVar9[9]) {
    FUN_80088554(piVar9[9]);
  }
  (**(code **)(*DAT_803dd6cc + 0xc))(0x14,1);
  DAT_803de890 = 2;
  goto LAB_801df3c4;
}
