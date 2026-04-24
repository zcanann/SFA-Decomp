// Function: FUN_8005d4ec
// Entry: 8005d4ec
// Size: 432 bytes

void FUN_8005d4ec(int param_1,int param_2,undefined4 param_3)

{
  uint3 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int local_28 [4];
  int local_18;
  
  iVar2 = (uint)*(ushort *)(param_2 + 0x84) << 3;
  FUN_80013a64(local_28,*(undefined4 *)(param_2 + 0x78),iVar2,iVar2);
  FUN_80013a5c(local_28,*(undefined2 *)(param_1 + 0x14));
  local_18 = local_18 + 4;
  FUN_8005e730(param_1,param_2,param_3);
  uVar3 = FUN_8005e560(param_2,local_28);
  local_18 = local_18 + 4;
  FUN_8005f920(1,param_2,uVar3,local_28);
  uVar5 = local_18 + 4;
  iVar2 = (int)uVar5 >> 3;
  iVar4 = local_28[0] + iVar2;
  local_18 = local_18 + 8;
  uVar1 = CONCAT12(*(undefined *)(iVar4 + 2),
                   CONCAT11(*(undefined *)(iVar4 + 1),*(undefined *)(local_28[0] + iVar2))) >>
          (uVar5 & 7);
  uVar5 = uVar1 & 0xf;
  iVar2 = 0;
  if ((uVar1 & 0xf) != 0) {
    if ((8 < uVar5) && (uVar6 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
      do {
        local_18 = local_18 + 0x40;
        iVar2 = iVar2 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    iVar4 = uVar5 - iVar2;
    if (iVar2 < (int)uVar5) {
      do {
        local_18 = local_18 + 8;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  local_18 = local_18 + 4;
  FUN_8005e348(param_2,uVar3,local_28,param_3);
  return;
}

