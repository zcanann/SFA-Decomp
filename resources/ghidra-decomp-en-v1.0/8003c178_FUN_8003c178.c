// Function: FUN_8003c178
// Entry: 8003c178
// Size: 240 bytes

void FUN_8003c178(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = FUN_80022a48();
  if (*(char *)(param_1 + 0xf4) != '\0') {
    FUN_8003befc(param_1,param_2);
  }
  uVar3 = (uint)*(byte *)(param_1 + 0xf3) + (uint)*(byte *)(param_1 + 0xf4);
  if ((uVar3 < 2) || (100 < uVar3)) {
    DAT_803dcc48 = 3;
  }
  else {
    iVar2 = FUN_8002856c(param_2,0);
    FUN_802419e8(iVar2,uVar3 * 0x40);
    iVar1 = iVar1 + 0x2700;
    for (uVar3 = uVar3 * 2 & 0xfe; 0x7f < (uVar3 & 0xff); uVar3 = uVar3 - 0x80) {
      FUN_800229f8(iVar1,iVar2,0);
      iVar2 = iVar2 + 0x1000;
      iVar1 = iVar1 + 0x1000;
    }
    if ((uVar3 & 0xff) != 0) {
      FUN_800229f8(iVar1,iVar2);
    }
    DAT_803dcc48 = 1;
  }
  return;
}

