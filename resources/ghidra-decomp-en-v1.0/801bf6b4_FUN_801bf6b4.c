// Function: FUN_801bf6b4
// Entry: 801bf6b4
// Size: 540 bytes

void FUN_801bf6b4(int param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar2;
  float fVar1;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  float *pfVar6;
  int local_18 [2];
  undefined4 local_10;
  uint uStack12;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  uVar4 = 0x16;
  if (param_3 != 0) {
    uVar4 = 0x17;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e4ce0,param_1,param_2,iVar5,0,0,0x102,uVar4);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  fVar1 = FLOAT_803e4cd8;
  pfVar6 = *(float **)(iVar5 + 0x40c);
  *pfVar6 = FLOAT_803e4cd8;
  pfVar6[1] = fVar1;
  uVar2 = FUN_800221a0(0xffff8001,0x7fff);
  *(undefined2 *)(pfVar6 + 5) = uVar2;
  fVar1 = FLOAT_803e4cd8;
  pfVar6[2] = FLOAT_803e4cd8;
  *(undefined2 *)((int)pfVar6 + 0x16) = 0;
  pfVar6[4] = fVar1;
  iVar5 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  pfVar6[3] = FLOAT_803e4cd8;
  if (iVar5 != 0) {
    pfVar6[3] = FLOAT_803e4d24;
    iVar3 = 0;
    if (0 < iVar5) {
      do {
        fVar1 = **(float **)(local_18[0] + iVar3) - *(float *)(param_1 + 0x10);
        if ((*(char *)(*(float **)(local_18[0] + iVar3) + 5) == '\x0e') && (pfVar6[3] < fVar1)) {
          pfVar6[3] = fVar1;
        }
        iVar3 = iVar3 + 4;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
  }
  pfVar6[3] = pfVar6[3] + *(float *)(param_1 + 0x10);
  uStack12 = FUN_800221a0(0,99);
  uStack12 = uStack12 ^ 0x80000000;
  local_10 = 0x43300000;
  FUN_80030334((double)((float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e4cf8) /
                       FLOAT_803e4d28),param_1,0,0);
  FUN_8002fa48((double)FLOAT_803e4d20,(double)FLOAT_803db414,param_1,0);
  fVar1 = (float)FUN_8001f4c8(param_1,1);
  pfVar6[6] = fVar1;
  if (pfVar6[6] != 0.0) {
    FUN_8001db2c(pfVar6[6],2);
    FUN_8001daf0(pfVar6[6],0,0xff,0,0);
    FUN_8001db14(pfVar6[6],1);
    FUN_8001dc38((double)FLOAT_803e4d2c,(double)FLOAT_803e4ce0,pfVar6[6]);
    FUN_8001d730((double)FLOAT_803e4d30,pfVar6[6],0,0,0xff,0,0x7f);
    FUN_8001d714((double)FLOAT_803e4d04,pfVar6[6]);
  }
  return;
}

