// Function: FUN_8003c270
// Entry: 8003c270
// Size: 240 bytes

void FUN_8003c270(int param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  iVar2 = FUN_80022b0c();
  if (*(char *)(param_1 + 0xf4) != '\0') {
    FUN_8003bff4();
  }
  uVar4 = (uint)*(byte *)(param_1 + 0xf3) + (uint)*(byte *)(param_1 + 0xf4);
  if ((uVar4 < 2) || (100 < uVar4)) {
    DAT_803dd8c8 = 3;
  }
  else {
    uVar3 = FUN_80028630(param_2,0);
    FUN_802420e0(uVar3,uVar4 * 0x40);
    uVar5 = iVar2 + 0x2700;
    for (uVar4 = uVar4 * 2 & 0xfe; uVar1 = uVar4 & 0xff, 0x7f < uVar1; uVar4 = uVar4 - 0x80) {
      FUN_80022abc(uVar5,uVar3,0);
      uVar3 = uVar3 + 0x1000;
      uVar5 = uVar5 + 0x1000;
    }
    if (uVar1 != 0) {
      FUN_80022abc(uVar5,uVar3,uVar1);
    }
    DAT_803dd8c8 = 1;
  }
  return;
}

