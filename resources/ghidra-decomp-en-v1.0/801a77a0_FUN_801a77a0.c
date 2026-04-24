// Function: FUN_801a77a0
// Entry: 801a77a0
// Size: 288 bytes

/* WARNING: Removing unreachable block (ram,0x801a781c) */

void FUN_801a77a0(int param_1)

{
  undefined4 uVar1;
  byte bVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  *(code **)(param_1 + 0xbc) = FUN_801a6f4c;
  *pbVar3 = 0;
  bVar2 = FUN_8001ffb4(0x88c);
  pbVar3[2] = bVar2;
  bVar2 = FUN_8001ffb4(0x87b);
  pbVar3[1] = bVar2;
  bVar2 = pbVar3[1];
  if (bVar2 == 2) {
    *(undefined *)(param_1 + 0x36) = 0xff;
    *pbVar3 = 4;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  else if (bVar2 < 2) {
    if (bVar2 == 0) {
      *(undefined *)(param_1 + 0x36) = 0;
      *(undefined *)(param_1 + 0xad) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0xff;
      *pbVar3 = 4;
      *(undefined *)(param_1 + 0xad) = 1;
      *pbVar3 = *pbVar3 | 0x40;
    }
  }
  else if (bVar2 < 4) {
    *(undefined *)(param_1 + 0x36) = 0xff;
    *pbVar3 = 4;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  uVar1 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(pbVar3 + 0xc) = uVar1;
  *(undefined4 *)(pbVar3 + 0x10) = uVar1;
  return;
}

