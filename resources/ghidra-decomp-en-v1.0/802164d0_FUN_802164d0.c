// Function: FUN_802164d0
// Entry: 802164d0
// Size: 336 bytes

/* WARNING: Removing unreachable block (ram,0x802165fc) */

void FUN_802164d0(double param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = *(int *)(param_2 + 0xb8);
  if (*(int *)(iVar2 + 0x10) != 0) {
    FUN_80023800();
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  local_3c = *(undefined4 *)(param_2 + 0xc);
  local_38 = *(undefined4 *)(param_2 + 0x10);
  local_34 = *(undefined4 *)(param_2 + 0x14);
  local_48 = FLOAT_803e6898;
  uStack44 = param_3 ^ 0x80000000;
  local_30 = 0x43300000;
  local_44 = -((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e68a8) *
               *(float *)(iVar2 + 0xc) * FLOAT_803e689c);
  local_40 = (float)param_1;
  FUN_80021ac8(param_2,&local_48);
  local_48 = local_48 + *(float *)(param_2 + 0xc);
  local_44 = local_44 + *(float *)(param_2 + 0x10);
  local_40 = local_40 + *(float *)(param_2 + 0x14);
  uStack36 = FUN_800221a0(10,param_3);
  uStack36 = uStack36 ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(iVar2 + 8) = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e68a8);
  uVar1 = FUN_8008fb20((double)FLOAT_803e68a0,(double)FLOAT_803e68a4,&local_3c,&local_48,
                       param_3 & 0xffff,0x60,0);
  *(undefined4 *)(iVar2 + 0x10) = uVar1;
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

