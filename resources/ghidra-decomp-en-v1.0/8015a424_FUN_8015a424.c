// Function: FUN_8015a424
// Entry: 8015a424
// Size: 264 bytes

void FUN_8015a424(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e2c7c;
  *(undefined4 *)(param_2 + 0x2e4) = 0x405009;
  *(float *)(param_2 + 0x304) = FLOAT_803e2c80;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e2c84;
  *(float *)(param_2 + 0x314) = FLOAT_803e2c84;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = FLOAT_803e2c3c;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(float *)(param_2 + 0x2fc) = *(float *)(param_2 + 0x2fc) * FLOAT_803e2c88;
  iVar2 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
  FUN_8014d08c((double)*(float *)(&DAT_8031fb70 + iVar2),param_1,param_2,(&DAT_8031fb78)[iVar2],0,0)
  ;
  *(float *)(param_2 + 0x328) = FLOAT_803e2c58;
  FUN_80035dc8(param_1,0xe,1,0xfff);
  uVar3 = FUN_80026cfc(&PTR_PTR_DAT_8031fc2c,5);
  *(undefined4 *)(param_2 + 0x36c) = uVar3;
  FUN_80026c38((double)FLOAT_803e2c8c,(double)FLOAT_803e2c90,(double)FLOAT_803e2c94,
               *(undefined4 *)(param_2 + 0x36c));
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x100;
  *(code **)(param_1 + 0x108) = FUN_8014d0f0;
  return;
}

