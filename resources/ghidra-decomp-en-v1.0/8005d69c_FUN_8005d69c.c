// Function: FUN_8005d69c
// Entry: 8005d69c
// Size: 504 bytes

void FUN_8005d69c(int param_1,int param_2,undefined4 param_3)

{
  uint3 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int local_58 [4];
  int local_48;
  undefined auStack68 [56];
  
  FUN_80246eb4(&DAT_80396850,param_3,auStack68);
  FUN_8025d160(auStack68,0x1e,0);
  FUN_80246eb4(&DAT_80396820,param_3,auStack68);
  FUN_8025d160(auStack68,0x21,0);
  FUN_8007cf7c();
  iVar2 = (uint)*(ushort *)(param_2 + 0x88) << 3;
  FUN_80013a64(local_58,*(undefined4 *)(param_2 + 0x80),iVar2,iVar2);
  FUN_80013a5c(local_58,*(undefined2 *)(param_1 + 0x14));
  local_48 = local_48 + 4;
  uVar3 = FUN_8005f558(1,param_2,local_58);
  local_48 = local_48 + 4;
  FUN_8005f920(1,param_2,uVar3,local_58);
  uVar5 = local_48 + 4;
  iVar2 = (int)uVar5 >> 3;
  iVar4 = local_58[0] + iVar2;
  local_48 = local_48 + 8;
  uVar1 = CONCAT12(*(undefined *)(iVar4 + 2),
                   CONCAT11(*(undefined *)(iVar4 + 1),*(undefined *)(local_58[0] + iVar2))) >>
          (uVar5 & 7);
  uVar5 = uVar1 & 0xf;
  iVar2 = 0;
  if ((uVar1 & 0xf) != 0) {
    if ((8 < uVar5) && (uVar6 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
      do {
        local_48 = local_48 + 0x40;
        iVar2 = iVar2 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    iVar4 = uVar5 - iVar2;
    if (iVar2 < (int)uVar5) {
      do {
        local_48 = local_48 + 8;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  local_48 = local_48 + 4;
  FUN_8005ec80(1,1,param_2,uVar3,local_58,param_3);
  return;
}

