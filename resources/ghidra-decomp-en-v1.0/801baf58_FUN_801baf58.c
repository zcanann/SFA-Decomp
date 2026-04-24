// Function: FUN_801baf58
// Entry: 801baf58
// Size: 384 bytes

/* WARNING: Removing unreachable block (ram,0x801bb0b8) */

undefined4 FUN_801baf58(undefined8 param_1,int param_2,int param_3)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_80035df4(param_2,9,1,0xffffffff);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x284) = fVar1;
    iVar2 = FUN_800221a0(0,1);
    if (iVar2 == 0) {
      if (*(char *)(param_3 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4bd8,param_2,0x10,0);
        *(undefined *)(param_3 + 0x346) = 0;
      }
      *(float *)(param_3 + 0x2a0) = FLOAT_803e4c04;
    }
    else {
      if (*(char *)(param_3 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4bd8,param_2,0xb,0);
        *(undefined *)(param_3 + 0x346) = 0;
      }
      *(float *)(param_3 + 0x2a0) = FLOAT_803e4c00;
    }
  }
  if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
    *(uint *)(param_3 + 0x314) = *(uint *)(param_3 + 0x314) & 0xfffffdff;
    DAT_803ddb80 = DAT_803ddb80 | 5;
  }
  uVar3 = FUN_800221a0(0,1);
  (**(code **)(*DAT_803dca8c + 0x34))(param_2,param_3,0,uVar3,&DAT_80325aa0);
  (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,0xf0);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return 0;
}

