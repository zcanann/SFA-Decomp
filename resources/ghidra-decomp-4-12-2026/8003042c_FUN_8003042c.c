// Function: FUN_8003042c
// Entry: 8003042c
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x80030760) */
/* WARNING: Removing unreachable block (ram,0x8003043c) */

void FUN_8003042c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double extraout_f1;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  uVar2 = (uint)uVar10;
  dVar8 = (double)FLOAT_803df560;
  if ((extraout_f1 <= dVar8) && (dVar8 = extraout_f1, extraout_f1 < (double)FLOAT_803df570)) {
    dVar8 = (double)FLOAT_803df570;
  }
  *(float *)(iVar5 + 0x98) = (float)dVar8;
  piVar3 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
  if ((piVar3 != (int *)0x0) && (iVar7 = *piVar3, *(short *)(iVar7 + 0xec) != 0)) {
    iVar6 = piVar3[0xb];
    *(char *)(iVar6 + 99) = (char)param_11;
    *(undefined2 *)(iVar6 + 0x46) = *(undefined2 *)(iVar6 + 0x44);
    *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(iVar6 + 4);
    *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar6 + 0x14);
    *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(iVar6 + 0x38) = *(undefined4 *)(iVar6 + 0x34);
    *(undefined *)(iVar6 + 0x61) = *(undefined *)(iVar6 + 0x60);
    *(undefined2 *)(iVar6 + 0x4a) = *(undefined2 *)(iVar6 + 0x48);
    *(undefined4 *)(iVar6 + 0x40) = *(undefined4 *)(iVar6 + 0x3c);
    *(undefined2 *)(iVar6 + 0x5c) = *(undefined2 *)(iVar6 + 0x5a);
    *(undefined2 *)(iVar6 + 0x5a) = 0;
    *(undefined2 *)(iVar6 + 100) = 0xffff;
    iVar4 = *(int *)(iVar5 + 0x54);
    dVar9 = extraout_f1;
    if ((iVar4 != 0) && (*(int *)(iVar4 + 8) != 0)) {
      param_14 = 0;
      dVar9 = (double)FUN_8003586c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                   param_8,iVar5,piVar3,(int)*(short *)(iVar5 + 0x46),iVar4,uVar2,0,
                                   param_15,param_16);
    }
    if (*(uint **)(iVar5 + 0x60) != (uint *)0x0) {
      dVar9 = (double)FUN_8002c7a0(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   iVar5,(int)*(short *)(iVar5 + 0x46),*(uint **)(iVar5 + 0x60),
                                   uVar2,0,param_14,param_15,param_16);
    }
    sVar1 = *(short *)(iVar5 + 0xa0);
    *(short *)(iVar5 + 0xa0) = (short)uVar10;
    iVar5 = (int)*(short *)(iVar7 + ((int)uVar2 >> 8) * 2 + 0x70) + (uVar2 & 0xff);
    if ((int)(uint)*(ushort *)(iVar7 + 0xec) <= iVar5) {
      iVar5 = *(ushort *)(iVar7 + 0xec) - 1;
    }
    if (iVar5 < 0) {
      iVar5 = 0;
    }
    if ((*(ushort *)(iVar7 + 2) & 0x40) == 0) {
      *(short *)(iVar6 + 0x44) = (short)iVar5;
      iVar5 = *(int *)(*(int *)(iVar7 + 100) + (uint)*(ushort *)(iVar6 + 0x44) * 4);
    }
    else {
      if ((int)(uVar2 - (int)sVar1 | (int)sVar1 - uVar2) < 0) {
        *(char *)(iVar6 + 0x62) = '\x01' - *(char *)(iVar6 + 0x62);
        *(short *)(iVar6 + 0x44) = (short)*(char *)(iVar6 + 0x62);
        if (*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2) == -1) {
          dVar9 = (double)FUN_8007d858();
          iVar5 = 0;
        }
        FUN_80024f40(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2),(int)(short)iVar5,
                     *(undefined4 *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c),iVar7);
      }
      iVar5 = *(int *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(iVar6 + 0x34) = iVar5 + 6;
    *(byte *)(iVar6 + 0x60) = *(byte *)(iVar5 + 1) & 0xf0;
    *(float *)(iVar6 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar6 + 0x34) + 1)) -
                DOUBLE_803df568);
    if (*(char *)(iVar6 + 0x60) == '\0') {
      *(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) - FLOAT_803df560;
    }
    uVar2 = (int)*(char *)(iVar5 + 1) & 0xf;
    if ((uVar2 == 0) || ((param_11 & 0x10) != 0)) {
      *(undefined2 *)(iVar6 + 0x58) = 0;
    }
    else {
      *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
      *(short *)(iVar6 + 0x5e) =
           (short)(int)(FLOAT_803df574 /
                       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df580));
      *(undefined2 *)(iVar6 + 0x58) = 0x4000;
    }
    *(float *)(iVar6 + 0xc) = FLOAT_803df570;
    *(float *)(iVar6 + 4) = (float)(dVar8 * (double)*(float *)(iVar6 + 0x14));
  }
  FUN_8028688c();
  return;
}

