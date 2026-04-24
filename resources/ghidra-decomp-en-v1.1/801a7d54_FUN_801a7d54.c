// Function: FUN_801a7d54
// Entry: 801a7d54
// Size: 288 bytes

/* WARNING: Removing unreachable block (ram,0x801a7dd0) */

void FUN_801a7d54(int param_1)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  *(code **)(param_1 + 0xbc) = FUN_801a7500;
  *pbVar4 = 0;
  uVar3 = FUN_80020078(0x88c);
  pbVar4[2] = (byte)uVar3;
  uVar3 = FUN_80020078(0x87b);
  pbVar4[1] = (byte)uVar3;
  bVar1 = pbVar4[1];
  if (bVar1 == 2) {
    *(undefined *)(param_1 + 0x36) = 0xff;
    *pbVar4 = 4;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      *(undefined *)(param_1 + 0x36) = 0;
      *(undefined *)(param_1 + 0xad) = 0;
    }
    else {
      *(undefined *)(param_1 + 0x36) = 0xff;
      *pbVar4 = 4;
      *(undefined *)(param_1 + 0xad) = 1;
      *pbVar4 = *pbVar4 | 0x40;
    }
  }
  else if (bVar1 < 4) {
    *(undefined *)(param_1 + 0x36) = 0xff;
    *pbVar4 = 4;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  uVar2 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(pbVar4 + 0xc) = uVar2;
  *(undefined4 *)(pbVar4 + 0x10) = uVar2;
  return;
}

