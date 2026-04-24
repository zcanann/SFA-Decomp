// Function: FUN_8021e5c4
// Entry: 8021e5c4
// Size: 168 bytes

void FUN_8021e5c4(undefined4 param_1,int param_2,int param_3)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_3 + 0x314);
  if ((uVar1 & 0x81) != 0) {
    if ((uVar1 & 1) != 0) {
      param_2 = 0;
    }
    if ((uVar1 & 0x80) != 0) {
      param_2 = 1;
    }
    FUN_8000bb18(param_1,(&DAT_803dc310)[param_2]);
  }
  if ((*(uint *)(param_3 + 0x314) & 0x100) != 0) {
    FUN_8009a8c8((double)FLOAT_803e6b30,param_1);
    FUN_8000bb18(param_1,DAT_803dc310);
  }
  return;
}

