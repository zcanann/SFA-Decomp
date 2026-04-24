// Function: FUN_8029ecc8
// Entry: 8029ecc8
// Size: 1636 bytes

/* WARNING: Removing unreachable block (ram,0x8029f304) */
/* WARNING: Removing unreachable block (ram,0x8029ecd8) */
/* WARNING: Type propagation algorithm not settling */

undefined4
FUN_8029ecc8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            uint *param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  uint local_38 [2];
  float afStack_30 [4];
  
  iVar9 = *(int *)(param_9 + 0xb8);
  local_38[0] = 0;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0x9e) = 0x1b;
    *(code **)(iVar9 + 0x898) = FUN_802a0820;
    FUN_80035f84(param_9);
  }
  iVar7 = *(int *)(param_9 + 0xb8);
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) & 0xfffffffd;
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar1 = FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar1;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *(undefined *)((int)param_10 + 0x25f) = 0;
  *(float *)(param_9 + 0x28) = fVar1;
  sVar2 = *(short *)(param_9 + 0xa0);
  if (sVar2 == 0x40d) {
LAB_8029edb0:
    fVar1 = (float)param_10[0xa3];
    fVar3 = fVar1 / FLOAT_803e8c40;
    if (fVar3 < FLOAT_803e8b3c) {
      fVar3 = -fVar3;
    }
    fVar4 = FLOAT_803e8b94;
    if ((FLOAT_803e8b94 <= fVar3) && (fVar4 = fVar3, FLOAT_803e8b78 < fVar3)) {
      fVar4 = FLOAT_803e8b78;
    }
    if (fVar1 <= FLOAT_803e8b78) {
      if (FLOAT_803e8b64 <= fVar1) {
        dVar11 = (double)FLOAT_803e8b3c;
        bVar5 = false;
      }
      else {
        dVar11 = (double)(FLOAT_803e8bdc * -fVar4);
        bVar5 = true;
      }
    }
    else {
      dVar11 = (double)(FLOAT_803e8bdc * fVar4);
      bVar5 = true;
    }
    if ((bVar5) && (DAT_803df100 = DAT_803df100 - DAT_803dc070, (int)DAT_803df100 < 1)) {
      DAT_803df100 = FUN_80022264(0x1e,0x2d);
      FUN_8000bb38(0,0x378);
    }
    dVar12 = (double)FLOAT_803dc074;
    dVar11 = FUN_80021434((double)(float)(dVar11 - (double)(float)param_10[0xa5]),
                          (double)FLOAT_803e8b94,dVar12);
    param_10[0xa5] = (uint)(float)((double)(float)param_10[0xa5] + dVar11);
    dVar11 = (double)(float)param_10[0xa5];
    *(float *)(iVar9 + 0x640) =
         (float)(dVar11 * (double)FLOAT_803dc074 + (double)*(float *)(iVar9 + 0x640));
    if ((FLOAT_803e8b90 <= (float)param_10[0xa5]) || ((float)param_10[0xa5] <= FLOAT_803e8c84)) {
      if (*(short *)(param_9 + 0xa0) != 0x40d) {
        FUN_8003042c((double)FLOAT_803e8b3c,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x40d,0,param_12,param_13,param_14,param_15,param_16);
      }
      FUN_8002f6cc((double)(float)param_10[0xa5],param_9,(float *)(param_10 + 0xa8));
    }
    else {
      dVar10 = (double)FLOAT_803e8b3c;
      param_10[0xa5] = (uint)FLOAT_803e8b3c;
      if (*(short *)(param_9 + 0xa0) != 0x76) {
        FUN_8003042c(dVar10,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,0x76,0,
                     param_12,param_13,param_14,param_15,param_16);
      }
      param_10[0xa8] = (uint)FLOAT_803e8c10;
    }
    bVar5 = false;
    if ((*(float *)(iVar9 + 0x644) < *(float *)(iVar9 + 0x640)) ||
       (*(float *)(iVar9 + 0x640) < FLOAT_803e8b3c)) {
      bVar5 = true;
    }
    if (bVar5) {
      FUN_8003042c((double)FLOAT_803e8b3c,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x40f,0,param_12,param_13,param_14,param_15,param_16);
      if ((*(char *)(iVar9 + 0x8c8) != 'H') && (*(char *)(iVar9 + 0x8c8) != 'G')) {
        local_38[0] = (uint)(FLOAT_803e8b3c <= *(float *)(iVar9 + 0x640));
        (**(code **)(*DAT_803dd6d0 + 0x60))(local_38);
      }
    }
    else {
      iVar7 = FUN_80021884();
      *(short *)(iVar9 + 0x478) = (short)iVar7;
      *(undefined2 *)(iVar9 + 0x484) = *(undefined2 *)(iVar9 + 0x478);
      *(undefined2 *)(param_9 + 2) = 0;
    }
  }
  else {
    if (sVar2 < 0x40d) {
      if (sVar2 == 0x76) goto LAB_8029edb0;
    }
    else {
      if (sVar2 == 0x40f) {
        param_10[0xa8] = (uint)FLOAT_803e8bcc;
        (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
        if (*(char *)((int)param_10 + 0x346) != '\0') {
          if ((*(char *)(iVar9 + 0x8c8) != 'H') && (*(char *)(iVar9 + 0x8c8) != 'G')) {
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,1,1,0,0,0,0xff);
          }
          *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x800000;
          param_10[0xc2] = (uint)FUN_802a58ac;
          return 2;
        }
        goto LAB_8029f2d0;
      }
      if (sVar2 < 0x40f) {
        param_10[0xa8] = (uint)FLOAT_803e8bcc;
        iVar8 = *DAT_803dd70c;
        (**(code **)(iVar8 + 0x20))(param_1,param_9,param_10,1);
        dVar11 = (double)*(float *)(iVar9 + 0x614);
        iVar7 = FUN_80021884();
        *(short *)(iVar9 + 0x478) = (short)iVar7;
        *(undefined2 *)(iVar9 + 0x484) = *(undefined2 *)(iVar9 + 0x478);
        FUN_80293900((double)(*(float *)(iVar9 + 0x60c) * *(float *)(iVar9 + 0x60c) +
                             *(float *)(iVar9 + 0x614) * *(float *)(iVar9 + 0x614)));
        *(undefined2 *)(param_9 + 2) = 0;
        if (*(char *)((int)param_10 + 0x346) != '\0') {
          FUN_8003042c((double)FLOAT_803e8b3c,dVar11,param_3,param_4,param_5,param_6,param_7,param_8
                       ,param_9,0x40d,0,iVar8,param_13,param_14,param_15,param_16);
        }
        goto LAB_8029f2d0;
      }
    }
    local_38[1] = 0x1f;
    dVar11 = (double)*(float *)(param_9 + 0x10);
    dVar12 = (double)*(float *)(param_9 + 0x14);
    iVar8 = *DAT_803dd71c;
    iVar7 = (**(code **)(iVar8 + 0x14))((double)*(float *)(param_9 + 0xc),local_38 + 1,1,0);
    if (iVar7 != -1) {
      iVar7 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(iVar9 + 0x61c) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar9 + 0x620) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar9 + 0x624) = *(undefined4 *)(iVar7 + 0x10);
      *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
      dVar11 = (double)*(float *)(iVar9 + 0x614);
      iVar6 = FUN_80021884();
      *(short *)(iVar9 + 0x478) = (short)iVar6;
      *(undefined2 *)(iVar9 + 0x484) = *(undefined2 *)(iVar9 + 0x478);
      FUN_80293900((double)(*(float *)(iVar9 + 0x60c) * *(float *)(iVar9 + 0x60c) +
                           *(float *)(iVar9 + 0x614) * *(float *)(iVar9 + 0x614)));
      *(undefined2 *)(param_9 + 2) = 0;
      iVar6 = (**(code **)(*DAT_803dd71c + 0x54))(iVar7,0xffffffff);
      if (iVar6 == -1) {
        (**(code **)(*DAT_803dd71c + 0x60))(iVar7,0xffffffff);
      }
      iVar7 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(iVar9 + 0x628) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar9 + 0x62c) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar9 + 0x630) = *(undefined4 *)(iVar7 + 0x10);
      *(float *)(iVar9 + 0x640) = FLOAT_803e8b3c;
      FUN_80247eb8((float *)(iVar9 + 0x628),(float *)(iVar9 + 0x61c),afStack_30);
      dVar10 = FUN_80247f54(afStack_30);
      *(float *)(iVar9 + 0x644) = (float)dVar10;
      FUN_80247ef8(afStack_30,(float *)(iVar9 + 0x634));
    }
    FUN_8003042c((double)FLOAT_803e8b3c,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x40e,0,iVar8,param_13,param_14,param_15,param_16);
    if ((*(char *)(iVar9 + 0x8c8) != 'H') && (*(char *)(iVar9 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x50,1,0,0,0,0x28,0xff);
    }
    param_10[0xa5] = (uint)FLOAT_803e8b3c;
  }
LAB_8029f2d0:
  FUN_80247edc((double)*(float *)(iVar9 + 0x640),(float *)(iVar9 + 0x634),afStack_30);
  FUN_80247e94((float *)(iVar9 + 0x61c),afStack_30,(float *)(param_9 + 0xc));
  FUN_802abd04(param_9,iVar9,7);
  return 0;
}

