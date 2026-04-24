// Function: FUN_80148d8c
// Entry: 80148d8c
// Size: 828 bytes

void FUN_80148d8c(int param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  *(undefined *)(param_2 + 0x2ef) = 0;
  if (((*(uint *)(param_2 + 0x2dc) & 0x800) != 0) && ((*(uint *)(param_2 + 0x2e0) & 0x800) == 0)) {
    iVar3 = FUN_8002b9ac();
    if (iVar3 != 0) {
      FUN_80138ef8();
    }
    if ((*(uint *)(param_2 + 0x2e4) & 0x40000000) == 0) {
      if (*(short *)(iVar4 + 0x18) != -1) {
        FUN_8001ff3c();
      }
      if (*(short *)(iVar4 + 0x1a) != -1) {
        FUN_800200e8((int)*(short *)(iVar4 + 0x1a),0);
      }
    }
    *(undefined4 *)(param_2 + 0x29c) = 0;
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(float *)(param_2 + 0x308) = FLOAT_803e256c / (FLOAT_803e2570 * *(float *)(param_2 + 0x318));
    *(undefined *)(param_2 + 0x323) = 1;
    FUN_80030334((double)FLOAT_803e2574,param_1,*(undefined *)(param_2 + 0x321),0);
    if (*(int *)(param_1 + 0x54) != 0) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
    }
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 1;
    FUN_8000bb18(param_1,0x233);
    iVar3 = FUN_800221a0(0,100);
    if (0x32 < iVar3) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x100000) == 0) {
        uVar1 = *(ushort *)(iVar4 + 0x22) & 0xf00;
        if (uVar1 != 0) {
          FUN_80149cec(param_1,param_2,uVar1,0,1);
        }
        uVar2 = (int)*(short *)(iVar4 + 0x22) & 0xf000;
        if (uVar2 != 0) {
          FUN_80149cec(param_1,param_2,uVar2,0,2);
        }
        uVar1 = *(ushort *)(iVar4 + 0x22) & 0xff;
        if (uVar1 != 0) {
          FUN_80149cec(param_1,param_2,uVar1,0,3);
        }
      }
      else {
        FUN_80149cec(param_1,param_2,*(undefined *)(param_2 + 0x2f5),0,4);
      }
    }
  }
  iVar3 = 0xff - (int)(FLOAT_803e257c * *(float *)(param_1 + 0x98));
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0xff < iVar3) {
    iVar3 = 0xff;
  }
  *(char *)(param_1 + 0x36) = (char)iVar3;
  *(float *)(param_2 + 0x30c) =
       FLOAT_803e256c +
       (float)((double)CONCAT44(0x43300000,0xff - *(byte *)(param_1 + 0x36) ^ 0x80000000) -
              DOUBLE_803e2580) / FLOAT_803e257c;
  if (*(byte *)(param_1 + 0x36) < 5) {
    if ((*(uint *)(param_2 + 0x2e4) & 0x40000000) != 0) {
      if (*(short *)(iVar4 + 0x18) != -1) {
        FUN_8001ff3c();
      }
      if (*(short *)(iVar4 + 0x1a) != -1) {
        FUN_800200e8((int)*(short *)(iVar4 + 0x1a),0);
      }
    }
    *(float *)(param_2 + 0x30c) = FLOAT_803e2574;
    *(undefined4 *)(param_2 + 0x2dc) = 0;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined4 *)(param_1 + 0xf4) = 1;
    if (*(int *)(iVar4 + 0x14) == -1) {
      FUN_8002cbc4(param_1);
    }
    else {
      if ((int)*(short *)(iVar4 + 0x2c) != 0) {
        (**(code **)(*DAT_803dcaac + 100))
                  ((double)(FLOAT_803e2570 *
                           (float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar4 + 0x2c) ^ 0x80000000) -
                                  DOUBLE_803e2580)));
      }
      *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xfffff7ff;
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) & 0xfffffffc;
    }
  }
  return;
}

