// Function: FUN_802b8360
// Entry: 802b8360
// Size: 368 bytes

void FUN_802b8360(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((*(uint *)(param_2 + 0x314) & 4) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffb;
    FUN_8000bb18(param_1,0x12e);
  }
  if ((*(uint *)(param_2 + 0x314) & 2) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffd;
    FUN_8000bb18(param_1,0x12e);
  }
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffffe;
    iVar1 = FUN_800221a0(0,2);
    if (iVar1 == 0) {
      FUN_8000bb18(param_1,0x43c);
    }
  }
  if ((*(uint *)(param_2 + 0x314) & 0x80) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffff7f;
    FUN_8000bb18(param_1,0x130);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    FUN_8000bb18(param_1,0x133);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x40) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xffffffbf;
    FUN_8000bb18(param_1,0x135);
  }
  if ((*(uint *)(param_2 + 0x314) & 0x800) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffff7ff;
    uVar2 = FUN_8002b9ec();
    FUN_80036450(uVar2,param_1,0x19,2,1);
    FUN_8000bb18(param_1,0x136);
    FUN_8000e650((double)FLOAT_803e81cc,(double)FLOAT_803e81d0,(double)FLOAT_803e81d4);
    FUN_80014aa0((double)FLOAT_803e81d8);
  }
  return;
}

