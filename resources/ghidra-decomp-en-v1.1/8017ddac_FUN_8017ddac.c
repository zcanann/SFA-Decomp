// Function: FUN_8017ddac
// Entry: 8017ddac
// Size: 668 bytes

/* WARNING: Removing unreachable block (ram,0x8017e028) */
/* WARNING: Removing unreachable block (ram,0x8017ddbc) */

void FUN_8017ddac(uint param_1,int param_2)

{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  double dVar8;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    uVar1 = 2;
  }
  else {
    if (param_2 < 1) {
      if (-1 < param_2) {
        uVar1 = 2;
        goto LAB_8017de10;
      }
    }
    else if (param_2 < 3) {
      uVar1 = 2;
      goto LAB_8017de10;
    }
    uVar1 = 0;
  }
LAB_8017de10:
  *(undefined2 *)(iVar4 + 0x38) = uVar1;
  *(undefined *)(iVar4 + 0x3a) = 4;
  *(float *)(iVar4 + 8) = FLOAT_803dc074;
  *(float *)(iVar4 + 0xc) = FLOAT_803dc074;
  uVar2 = FUN_80022264(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x48) = (short)uVar2;
  uVar2 = FUN_80022264(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x4a) = (short)uVar2;
  *(undefined2 *)(iVar4 + 0x4c) = 0x2000;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  iVar3 = FUN_80065800(dVar5,dVar6,dVar7,param_1,(float *)(iVar4 + 0x30),0);
  if (iVar3 == 0) {
    iVar4 = *(int *)(param_1 + 0xb8);
    if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035ff8(param_1);
      }
      *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
    }
    else {
      FUN_8002cc9c(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
    }
  }
  else {
    dVar5 = (double)*(float *)(iVar4 + 0x40);
    dVar6 = FUN_80293900(-(double)((float)((double)FLOAT_803e4470 * dVar5) *
                                   *(float *)(iVar4 + 0x30) - FLOAT_803e446c));
    dVar7 = (double)(float)((double)FLOAT_803e4474 * dVar5);
    dVar5 = dVar7;
    if (dVar7 < (double)FLOAT_803e446c) {
      dVar5 = -dVar7;
    }
    if ((double)FLOAT_803e4478 < dVar5) {
      dVar8 = (double)(float)((double)(float)((double)FLOAT_803e447c - dVar6) / dVar7);
      dVar5 = (double)(float)((double)(float)((double)FLOAT_803e447c + dVar6) / dVar7);
      if ((double)FLOAT_803e446c < dVar8) {
        dVar5 = dVar8;
      }
    }
    else {
      dVar5 = (double)FLOAT_803e4460;
    }
    *(float *)(iVar4 + 0x50) = (float)dVar5;
    if (FLOAT_803e446c <= *(float *)(iVar4 + 0x28)) {
      dVar6 = (double)FLOAT_803e4480;
      *(float *)(iVar4 + 0x30) =
           (float)(dVar6 * (double)(FLOAT_803e4470 * *(float *)(iVar4 + 0x24)) +
                  (double)*(float *)(iVar4 + 0x30));
    }
    else {
      dVar6 = (double)FLOAT_803e4470;
      *(float *)(iVar4 + 0x30) =
           -(float)(dVar6 * (double)*(float *)(iVar4 + 0x24) - (double)*(float *)(iVar4 + 0x30));
    }
    if ((double)FLOAT_803e446c < (double)*(float *)(iVar4 + 0x30)) {
      *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar4 + 0x34) = *(float *)(param_1 + 0x10) - *(float *)(iVar4 + 0x30);
      if (*(int *)(param_1 + 0x54) != 0) {
        FUN_80035ff8(param_1);
      }
      FUN_8000bb38(param_1,0x52);
    }
    else {
      iVar3 = *(int *)(param_1 + 0xb8);
      if ((*(ushort *)(param_1 + 6) & 0x2000) == 0) {
        if (*(int *)(param_1 + 0x54) != 0) {
          FUN_80035ff8(param_1);
        }
        *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
      }
      else {
        FUN_8002cc9c((double)*(float *)(iVar4 + 0x30),dVar6,dVar7,dVar5,in_f5,in_f6,in_f7,in_f8,
                     param_1);
      }
    }
  }
  return;
}

