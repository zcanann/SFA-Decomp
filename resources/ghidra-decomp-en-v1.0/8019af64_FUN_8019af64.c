// Function: FUN_8019af64
// Entry: 8019af64
// Size: 628 bytes

/* WARNING: Removing unreachable block (ram,0x8019b1b8) */

void FUN_8019af64(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  short *psVar1;
  int iVar2;
  char cVar5;
  int iVar3;
  short sVar4;
  undefined4 uVar6;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar7;
  float local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined2 local_4c [6];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860d8();
  psVar1 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  cVar5 = '\0';
  local_58 = FLOAT_803e4110;
  if (*(int *)(psVar1 + 0x7a) == -1) {
    cVar5 = '\x01';
  }
  else {
    uVar7 = extraout_f1;
    if (*(int *)(psVar1 + 0x7a) == 0) {
      iVar2 = FUN_8019b3f8(psVar1,param_3 & 0xff,0,2);
      local_40 = *(undefined4 *)(iVar2 + 8);
      local_3c = *(undefined4 *)(iVar2 + 0xc);
      local_38 = *(undefined4 *)(iVar2 + 0x10);
      local_4c[0] = (undefined2)((int)*(char *)(iVar2 + 0x2c) << 8);
      iVar2 = FUN_8019b1d8(uVar7,psVar1,local_4c,param_4);
      if (iVar2 != 0) {
        local_54 = 0x19;
        local_50 = 0x15;
        (**(code **)(*DAT_803dca9c + 0x8c))
                  ((double)FLOAT_803e4120,iVar3,psVar1,&local_54,param_3 & 0xff);
        *(undefined4 *)(psVar1 + 0x7a) = 1;
      }
    }
    else {
      cVar5 = '\0';
      iVar2 = FUN_80010320(iVar3);
      if ((iVar2 != 0) || (*(int *)(iVar3 + 0x10) != 0)) {
        cVar5 = (**(code **)(*DAT_803dca9c + 0x90))(iVar3);
      }
      *(undefined4 *)(psVar1 + 6) = *(undefined4 *)(iVar3 + 0x68);
      *(undefined4 *)(psVar1 + 8) = *(undefined4 *)(iVar3 + 0x6c);
      *(undefined4 *)(psVar1 + 10) = *(undefined4 *)(iVar3 + 0x70);
      if (cVar5 != '\0') {
        *(undefined4 *)(psVar1 + 0x7a) = 0xffffffff;
      }
      iVar3 = FUN_800658a4((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                           (double)*(float *)(psVar1 + 10),psVar1,&local_58,0);
      if (iVar3 == 0) {
        *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - local_58;
      }
    }
    FUN_8002f5d4(uVar7,psVar1,param_4);
    sVar4 = FUN_800217c0((double)(*(float *)(psVar1 + 6) - *(float *)(psVar1 + 0x40)),
                         (double)(*(float *)(psVar1 + 10) - *(float *)(psVar1 + 0x44)));
    sVar4 = (sVar4 + -0x8000) - *psVar1;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *psVar1 = *psVar1 + (sVar4 >> 3);
    if (psVar1[0x50] != 0x1a) {
      FUN_80030334((double)FLOAT_803e4110,psVar1,0x1a,0);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286124(cVar5);
  return;
}

