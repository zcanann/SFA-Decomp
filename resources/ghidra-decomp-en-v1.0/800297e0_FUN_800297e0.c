// Function: FUN_800297e0
// Entry: 800297e0
// Size: 84 bytes

void FUN_800297e0(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = FUN_80240384();
  if ((uVar1 & 0x10000000) == 0) {
    uVar2 = FUN_80022a48();
    FUN_802419b8(uVar2,0x4000);
    FUN_80241c08();
  }
  FUN_80029764();
  FUN_8002a40c(7,4,7,4);
  return;
}

