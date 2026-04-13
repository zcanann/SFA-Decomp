// Function: FUN_80049b64
// Entry: 80049b64
// Size: 324 bytes

void FUN_80049b64(void)

{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  undefined4 local_28 [3];
  undefined auStack_1c [8];
  int local_14;
  
  if ((DAT_803de288 == 2) || (DAT_803de288 == 3)) {
    FUN_80118434();
  }
  FUN_8001378c(-0x7fc9fc70,(uint)auStack_1c);
  puVar4 = &DAT_80397330;
  puVar3 = &DAT_80397240;
  for (iVar2 = 0; iVar2 < (int)(uint)DAT_803ddc80; iVar2 = iVar2 + 1) {
    *puVar3 = *puVar4;
    puVar3[1] = puVar4[1];
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(puVar4 + 4);
    FUN_80258dac((uint)*puVar3,(uint)puVar3[1],(undefined4 *)(puVar3 + 2));
    puVar4 = puVar4 + 6;
    puVar3 = puVar3 + 6;
  }
  DAT_803ddc82 = DAT_803ddc80;
  DAT_803ddc80 = 0;
  if (local_14 == DAT_803dd94c) {
    DAT_803dd928 = 1;
    DAT_803dd929 = 0;
  }
  else {
    FUN_800137c8((short *)&DAT_80360390,(uint)local_28);
    DAT_803dd92c = 0;
    FUN_802472b0((int *)&DAT_803dd944);
    uVar1 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar1 == 0) {
      FUN_8001378c(-0x7fc9fc70,(uint)local_28);
      FUN_80256c08(local_28[0]);
      DAT_803dd927 = 1;
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
  }
  return;
}

