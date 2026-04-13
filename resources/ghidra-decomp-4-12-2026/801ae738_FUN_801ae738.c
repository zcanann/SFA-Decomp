// Function: FUN_801ae738
// Entry: 801ae738
// Size: 628 bytes

undefined4 FUN_801ae738(int param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  ushort uVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  short *psVar7;
  
  psVar7 = *(short **)(param_1 + 0xb8);
  piVar3 = (int *)FUN_800395a4(param_1,1);
  *piVar3 = (*(byte *)((int)psVar7 + 3) >> 1 & 1 ^ 1) << 8;
  if ((*(byte *)((int)psVar7 + 3) & 2) == 0) {
    sVar1 = *psVar7;
    uVar2 = (ushort)DAT_803dc070;
    *psVar7 = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 0) {
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) | 2;
      *psVar7 = 0x78;
    }
  }
  else {
    *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) & 0xfd;
  }
  if ((*(byte *)((int)psVar7 + 3) & 2) != 0) {
    DAT_803ad5b4 = FLOAT_803e5408;
    DAT_803ad5b8 = FLOAT_803e540c;
    DAT_803ad5bc = FLOAT_803e5410;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x133,&DAT_803ad5a8,4,0xffffffff,0);
    DAT_803ad5b4 = FLOAT_803e5414;
    DAT_803ad5b8 = FLOAT_803e540c;
    DAT_803ad5bc = FLOAT_803e5410;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x133,&DAT_803ad5a8,4,0xffffffff,0);
  }
  puVar4 = (undefined4 *)FUN_800395a4(param_1,0);
  *puVar4 = 0x100;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    uVar6 = (uint)*(byte *)(param_3 + iVar5 + 0x81);
    switch(uVar6) {
    case 1:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 2:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 3:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 4:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ (byte)(1 << uVar6 - 1);
      break;
    case 5:
      *(byte *)(psVar7 + 1) = *(byte *)(psVar7 + 1) ^ 0x70;
      break;
    case 6:
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) ^ 8;
      break;
    case 7:
      *(byte *)((int)psVar7 + 3) = *(byte *)((int)psVar7 + 3) ^ 4;
    }
  }
  return 0;
}

