// Function: FUN_802643e8
// Entry: 802643e8
// Size: 196 bytes

int FUN_802643e8(int param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int local_10 [3];
  
  if ((param_1 < 0) || (1 < param_1)) {
    iVar5 = -0x80;
  }
  else {
    iVar5 = FUN_8025edc8(param_1,local_10);
    if (-1 < iVar5) {
      puVar6 = *(uint **)(local_10[0] + 0x80);
      uVar1 = *puVar6;
      uVar2 = puVar6[2];
      uVar3 = puVar6[4];
      uVar4 = puVar6[6];
      param_2[1] = puVar6[1] ^ puVar6[3] ^ puVar6[5] ^ puVar6[7];
      *param_2 = uVar1 ^ uVar2 ^ uVar3 ^ uVar4;
      iVar5 = FUN_8025ee80(local_10[0],0);
    }
  }
  return iVar5;
}

