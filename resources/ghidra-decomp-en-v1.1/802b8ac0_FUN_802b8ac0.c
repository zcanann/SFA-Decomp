// Function: FUN_802b8ac0
// Entry: 802b8ac0
// Size: 368 bytes

void FUN_802b8ac0(uint param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  if ((*(uint *)(param_2 + 0x314) & 4) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffb;
    FUN_8000bb38(param_1,0x12e);
  }
  if ((*(uint *)(param_2 + 0x314) & 2) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffd;
    FUN_8000bb38(param_1,0x12e);
  }
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffe;
    uVar1 = FUN_80022264(0,2);
    if (uVar1 == 0) {
      FUN_8000bb38(param_1,0x43c);
    }
  }
  if ((*(uint *)(param_2 + 0x314) & 0x80) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffff7f;
    FUN_8000bb38(param_1,0x130);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    FUN_8000bb38(param_1,0x133);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x40) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffffbf;
    FUN_8000bb38(param_1,0x135);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x800) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffff7ff;
    iVar2 = FUN_8002bac4();
    FUN_80036548(iVar2,param_1,'\x19',2,1);
    FUN_8000bb38(param_1,0x136);
    FUN_8000e670((double)FLOAT_803e8e64,(double)FLOAT_803e8e68,(double)FLOAT_803e8e6c);
    FUN_80014acc((double)FLOAT_803e8e70);
  }
  return;
}

