// Function: FUN_80276e70
// Entry: 80276e70
// Size: 308 bytes

void FUN_80276e70(int param_1,int param_2,uint *param_3,undefined4 param_4,uint param_5,uint param_6
                 ,uint param_7)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte bVar6;
  
  if ((*(uint *)(param_1 + 0x118) & param_6) == 0 && (*(uint *)(param_1 + 0x114) & param_5) == 0) {
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | param_6;
    bVar6 = 0;
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | param_5;
  }
  else {
    bVar6 = (byte)param_3[1];
  }
  uVar2 = *param_3;
  iVar3 = (int)(uVar2 & 0xffff0000) / 100 + ((int)uVar2 >> 0x1f);
  iVar3 = iVar3 - (iVar3 >> 0x1f);
  if (iVar3 < 0) {
    uVar4 = (uint)(char)(param_3[1] >> 0x10);
    uVar1 = uVar4 << 8;
    iVar5 = (int)uVar1 / 100 + ((int)(uVar1 | uVar4 >> 0x18) >> 0x1f);
    iVar5 = -(iVar5 - (iVar5 >> 0x1f));
  }
  else {
    uVar4 = (uint)(char)(param_3[1] >> 0x10);
    uVar1 = uVar4 << 8;
    iVar5 = (int)uVar1 / 100 + ((int)(uVar1 | uVar4 >> 0x18) >> 0x1f);
    iVar5 = iVar5 - (iVar5 >> 0x1f);
  }
  FUN_80282594(param_2,uVar2 >> 8 & 0xff,iVar3 + iVar5,bVar6,(uint)((param_3[1] >> 8 & 0xff) != 0));
  if ((param_7 & 0x80000000) == 0) {
    *(uint *)(param_1 + 0x214) = *(uint *)(param_1 + 0x214) | param_7;
  }
  else {
    FUN_80281a74((uint)*(byte *)(param_1 + 0x121),(uint)*(byte *)(param_1 + 0x122),param_7);
  }
  return;
}

