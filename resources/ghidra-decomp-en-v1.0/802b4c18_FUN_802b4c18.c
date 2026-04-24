// Function: FUN_802b4c18
// Entry: 802b4c18
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x802b4dc0) */

void FUN_802b4c18(undefined8 param_1,int param_2,uint *param_3)

{
  char cVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack88 [64];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  param_3[0xa9] = (uint)FLOAT_803e7eb4;
  param_3[0xa4] = param_3[0x1b7];
  param_3[0xa3] = param_3[0x1b6];
  param_3[199] = (uint)*(ushort *)((int)param_3 + 0x6e2);
  param_3[0xc6] = (uint)*(ushort *)(param_3 + 0x1b8);
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6e) = 0;
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6f) = 0;
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6c) = 0;
  *(undefined *)(*(int *)(param_2 + 0x54) + 0x6d) = 0;
  *(undefined *)((int)param_3 + 0x25f) = 1;
  param_3[1] = param_3[1] & 0xf7efffff;
  FUN_80062a30();
  *(undefined *)((int)param_3 + 0x8c5) = 0;
  param_3[0xd8] = param_3[0xd8] & 0xffffdfff;
  *param_3 = *param_3 | 0x1000000;
  FUN_802b0ea4(param_2,param_3,param_3);
  cVar1 = FUN_802a74a4(param_1,param_2,param_3,param_3,auStack88,0x60);
  if (cVar1 == '\b') {
    param_3[0xb4] = 0;
    *(undefined *)((int)param_3 + 0x349) = 0;
    (**(code **)(*DAT_803dca50 + 0x48))(0);
    if ((DAT_803de44c != 0) && ((*(byte *)(param_3 + 0xfd) >> 6 & 1) != 0)) {
      *(undefined *)(param_3 + 0x22d) = 1;
      *(byte *)(param_3 + 0xfd) = *(byte *)(param_3 + 0xfd) & 0xf7 | 8;
    }
    (**(code **)(*DAT_803dca8c + 0x14))(param_2,param_3,10);
    param_3[0xc1] = 0;
  }
  (**(code **)(*DAT_803dca8c + 8))(param_1,param_1,param_2,param_3,&DAT_803dafc8,&DAT_803de4b8);
  *param_3 = *param_3 & 0xfeffffff;
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

