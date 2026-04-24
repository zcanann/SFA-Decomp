// Function: FUN_8017b170
// Entry: 8017b170
// Size: 348 bytes

undefined4 FUN_8017b170(int param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 1) {
      iVar2 = (uint)bVar4 * 4 + 4;
      iVar6 = *(int *)(iVar7 + iVar2);
      if (iVar6 != 0) {
        iVar3 = iVar7 + (uint)bVar4 * 8;
        *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(iVar3 + 0x30) = *(undefined4 *)(*(int *)(iVar7 + iVar2) + 0x14);
      }
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  else if (*(char *)(param_3 + 0x80) == '\x02') {
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 5) {
      puVar5 = (undefined4 *)(iVar7 + (uint)bVar4 * 4 + 4);
      *puVar5 = 0;
      puVar5[1] = 0;
      puVar5[2] = 0;
      puVar5[3] = 0;
      puVar5[4] = 0;
    }
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar7 + 0x7c);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 0x10);
    FUN_800201ac((int)*(short *)(iVar6 + 0x1a),0);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  sVar1 = *(short *)(param_1 + 0x46);
  if ((((sVar1 != 0x19f) && (sVar1 != 0x26c)) && (sVar1 != 0x274)) && (sVar1 != 0x545)) {
    *(undefined4 *)(iVar7 + 0x7c) = *(undefined4 *)(param_1 + 0x10);
  }
  return 0;
}

