// Function: FUN_80164940
// Entry: 80164940
// Size: 772 bytes

/* WARNING: Removing unreachable block (ram,0x80164c1c) */
/* WARNING: Removing unreachable block (ram,0x80164c24) */

void FUN_80164940(int param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  undefined auStack76 [4];
  double local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  longlong local_30;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(iVar5 + 0x278);
  if (cVar1 == '\0') {
    iVar4 = (**(code **)(*DAT_803dca58 + 0x24))(auStack88);
    if (iVar4 != 0) {
      if (*(float *)(iVar5 + 0x26c) <= *(float *)(param_1 + 8)) {
        *(undefined *)(iVar5 + 0x278) = 1;
      }
      else {
        *(float *)(param_1 + 8) =
             *(float *)(iVar5 + 0x270) * FLOAT_803db414 + *(float *)(param_1 + 8);
      }
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = (**(code **)(*DAT_803dca58 + 0x24))(auStack88);
    if (iVar4 != 0) {
      iVar4 = *(int *)(iVar5 + 0x284);
      if (iVar4 == 0) {
        iVar4 = FUN_8002b9ec();
      }
      fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0xc);
      fVar3 = *(float *)(param_1 + 0x14) - *(float *)(iVar4 + 0x14);
      dVar7 = (double)FUN_802931a0((double)(fVar2 * fVar2 + fVar3 * fVar3));
      local_48 = (double)(longlong)(int)dVar7;
      *(short *)(iVar5 + 0x268) = (short)(int)dVar7;
      if (*(ushort *)(iVar5 + 0x268) < *(ushort *)(iVar5 + 0x26a)) {
        *(undefined *)(iVar5 + 0x278) = 2;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        FUN_80035f20(param_1);
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = *(int *)(iVar5 + 0x284);
    if (iVar4 == 0) {
      iVar4 = FUN_8002b9ec();
    }
    dVar9 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0xc));
    dVar8 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar4 + 0x14));
    dVar7 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
    local_48 = (double)(longlong)(int)dVar7;
    *(short *)(iVar5 + 0x268) = (short)(int)dVar7;
    fVar3 = FLOAT_803e2fc4;
    dVar7 = DOUBLE_803e2f90;
    fVar2 = FLOAT_803e2f84;
    uStack60 = (uint)*(ushort *)(iVar5 + 0x268);
    if ((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e2f90) <= FLOAT_803e2fc4) {
      *(float *)(param_1 + 0x24) = -(FLOAT_803e2f84 * *(float *)(param_1 + 0x24));
      *(float *)(param_1 + 0x2c) = -(fVar2 * *(float *)(param_1 + 0x2c));
    }
    else {
      *(float *)(param_1 + 0x24) =
           *(float *)(param_1 + 0x24) -
           (float)(dVar9 / (double)(FLOAT_803e2fc4 *
                                   (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e2f90))
                  );
      local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x268));
      *(float *)(param_1 + 0x2c) =
           *(float *)(param_1 + 0x2c) - (float)(dVar8 / (double)(fVar3 * (float)(local_48 - dVar7)))
      ;
      fVar2 = FLOAT_803e2fac;
      iVar4 = (int)(FLOAT_803e2fac * *(float *)(param_1 + 0x24));
      local_38 = (longlong)iVar4;
      *(short *)(iVar5 + 0x27c) = (short)iVar4;
      iVar4 = (int)(fVar2 * *(float *)(param_1 + 0x2c));
      local_30 = (longlong)iVar4;
      *(short *)(iVar5 + 0x27e) = (short)iVar4;
    }
    local_40 = 0x43300000;
    FUN_80163bbc(param_1,iVar5);
    (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar5);
    iVar4 = FUN_8003687c(param_1,auStack84,auStack76,auStack80);
    if (iVar4 != 0) {
      FUN_800200e8(0x642,1);
      *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 7;
    }
  }
  else if (FLOAT_803e2f68 < *(float *)(iVar5 + 0x270)) {
    *(float *)(iVar5 + 0x270) = *(float *)(iVar5 + 0x270) - FLOAT_803db414;
  }
  else {
    FUN_8002cbc4();
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

