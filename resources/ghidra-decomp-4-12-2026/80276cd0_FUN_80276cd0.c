// Function: FUN_80276cd0
// Entry: 80276cd0
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x80276d64) */

void FUN_80276cd0(int param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  if ((param_2[1] >> 8 & 0xff) == 0) {
    uVar1 = *param_2;
    uVar5 = uVar1 >> 8 & 0xff;
    uVar2 = uVar1 >> 0x18;
    if (uVar1 >> 0x18 < uVar5) {
      uVar2 = uVar5;
      uVar5 = uVar1 >> 0x18;
    }
  }
  else {
    uVar5 = (uint)*(ushort *)(param_1 + 300) - (*param_2 >> 8 & 0xff);
    uVar2 = (uint)*(ushort *)(param_1 + 300) + (*param_2 >> 0x18);
    if ((int)uVar5 < 0) {
      uVar5 = 0;
    }
    else if (0x7f < (int)uVar5) {
      uVar5 = 0x7f;
    }
    uVar5 = uVar5 & 0xff;
    if (0x7f < uVar2) {
      uVar2 = 0x7f;
    }
    uVar2 = uVar2 & 0xff;
  }
  if ((param_2[1] & 0xff) == 0) {
    uVar1 = *param_2 >> 0x10 & 0xff;
  }
  else {
    uVar1 = FUN_802835c0();
    uVar1 = (uVar1 & 0xffff) % 0xc9 - 100;
  }
  uVar3 = FUN_802835c0();
  iVar4 = (uVar2 - uVar5) + 1;
  *param_2 = (uVar1 & 0xff) << 0x10 | 0x19 |
             (uVar5 + ((uVar3 & 0xffff) - ((int)(uVar3 & 0xffff) / iVar4) * iVar4)) * 0x100;
  param_2[1] = 0;
  *(ushort *)(param_1 + 300) = (ushort)(*param_2 >> 8) & 0x7f;
  *(char *)(param_1 + 0x12e) = (char)(*param_2 >> 0x10);
  iVar4 = FUN_8027a940(param_1);
  if (iVar4 != 0) {
    FUN_8028274c((uint)*(byte *)(param_1 + 0x121),(uint)*(byte *)(param_1 + 0x122),
                 (char)*(undefined2 *)(param_1 + 300));
  }
  *param_2 = 4;
  FUN_80275ac8(param_1,param_2);
  return;
}

