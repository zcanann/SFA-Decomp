// Function: FUN_80227bb8
// Entry: 80227bb8
// Size: 284 bytes

undefined4 FUN_80227bb8(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  byte bVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    for (bVar3 = 0; bVar3 < 10; bVar3 = bVar3 + 1) {
      iVar1 = (uint)bVar3 * 4 + 4;
      iVar6 = *(int *)(iVar5 + iVar1);
      if (iVar6 != 0) {
        iVar2 = iVar5 + (uint)bVar3 * 8;
        *(undefined4 *)(iVar2 + 0x2c) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(iVar2 + 0x30) = *(undefined4 *)(*(int *)(iVar5 + iVar1) + 0x14);
      }
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  else if (*(char *)(param_3 + 0x80) == '\x02') {
    for (bVar3 = 0; bVar3 < 10; bVar3 = bVar3 + 5) {
      puVar4 = (undefined4 *)(iVar5 + (uint)bVar3 * 4 + 4);
      *puVar4 = 0;
      puVar4[1] = 0;
      puVar4[2] = 0;
      puVar4[3] = 0;
      puVar4[4] = 0;
    }
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 0x10);
    FUN_800200e8((int)*(short *)(iVar6 + 0x1a),0);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  return 0;
}

