// Function: FUN_8002f334
// Entry: 8002f334
// Size: 720 bytes

/* WARNING: Removing unreachable block (ram,0x8002f5e4) */
/* WARNING: Removing unreachable block (ram,0x8002f344) */

undefined4
FUN_8002f334(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint param_10,
            undefined param_11)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  dVar7 = (double)FLOAT_803df560;
  if ((param_1 <= dVar7) && (dVar7 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar7 = (double)FLOAT_803df570;
  }
  *(float *)(param_9 + 0x9c) = (float)dVar7;
  piVar4 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  iVar6 = *piVar4;
  if (*(short *)(iVar6 + 0xec) != 0) {
    iVar5 = piVar4[0xc];
    *(undefined *)(iVar5 + 99) = param_11;
    *(undefined2 *)(iVar5 + 0x46) = *(undefined2 *)(iVar5 + 0x44);
    *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar5 + 4);
    *(undefined4 *)(iVar5 + 0x18) = *(undefined4 *)(iVar5 + 0x14);
    *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(iVar5 + 0x38) = *(undefined4 *)(iVar5 + 0x34);
    *(undefined *)(iVar5 + 0x61) = *(undefined *)(iVar5 + 0x60);
    *(undefined2 *)(iVar5 + 0x4a) = *(undefined2 *)(iVar5 + 0x48);
    *(undefined4 *)(iVar5 + 0x40) = *(undefined4 *)(iVar5 + 0x3c);
    *(undefined2 *)(iVar5 + 0x5c) = *(undefined2 *)(iVar5 + 0x5a);
    *(undefined2 *)(iVar5 + 0x5a) = 0;
    *(undefined2 *)(iVar5 + 100) = 0xffff;
    sVar1 = *(short *)(param_9 + 0xa2);
    *(short *)(param_9 + 0xa2) = (short)param_10;
    iVar3 = (int)*(short *)(iVar6 + ((int)param_10 >> 8) * 2 + 0x70) + (param_10 & 0xff);
    if ((int)(uint)*(ushort *)(iVar6 + 0xec) <= iVar3) {
      iVar3 = *(ushort *)(iVar6 + 0xec) - 1;
    }
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      *(short *)(iVar5 + 0x44) = (short)iVar3;
      iVar6 = *(int *)(*(int *)(iVar6 + 100) + (uint)*(ushort *)(iVar5 + 0x44) * 4);
    }
    else {
      if ((int)(param_10 - (int)sVar1 | (int)sVar1 - param_10) < 0) {
        *(char *)(iVar5 + 0x62) = '\x01' - *(char *)(iVar5 + 0x62);
        *(short *)(iVar5 + 0x44) = (short)*(char *)(iVar5 + 0x62);
        if (*(short *)(*(int *)(iVar6 + 0x6c) + iVar3 * 2) == -1) {
          param_1 = (double)FUN_8007d858();
          iVar3 = 0;
        }
        FUN_80024f40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(short *)(*(int *)(iVar6 + 0x6c) + iVar3 * 2),(int)(short)iVar3,
                     *(undefined4 *)(iVar5 + (uint)*(ushort *)(iVar5 + 0x44) * 4 + 0x1c),iVar6);
      }
      iVar6 = *(int *)(iVar5 + (uint)*(ushort *)(iVar5 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(iVar5 + 0x34) = iVar6 + 6;
    *(byte *)(iVar5 + 0x60) = *(byte *)(iVar6 + 1) & 0xf0;
    *(float *)(iVar5 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar5 + 0x34) + 1)) -
                DOUBLE_803df568);
    if (*(char *)(iVar5 + 0x60) == '\0') {
      *(float *)(iVar5 + 0x14) = *(float *)(iVar5 + 0x14) - FLOAT_803df560;
    }
    uVar2 = (int)*(char *)(iVar6 + 1) & 0xf;
    if (uVar2 != 0) {
      *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
      *(short *)(iVar5 + 0x5e) =
           (short)(int)(FLOAT_803df574 /
                       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df580));
      *(undefined2 *)(iVar5 + 0x58) = 0x4000;
    }
    *(float *)(iVar5 + 0xc) = FLOAT_803df570;
    *(float *)(iVar5 + 4) = (float)(dVar7 * (double)*(float *)(iVar5 + 0x14));
  }
  return 0;
}

