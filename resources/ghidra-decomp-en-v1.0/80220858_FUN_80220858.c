// Function: FUN_80220858
// Entry: 80220858
// Size: 528 bytes

void FUN_80220858(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined2 uVar3;
  int iVar4;
  int *piVar5;
  undefined4 local_48;
  float local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined auStack48 [12];
  undefined4 local_24;
  float local_20;
  undefined4 local_1c;
  
  piVar5 = *(int **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(char *)(piVar5 + 1) < '\0') {
    *(undefined4 *)*piVar5 = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*piVar5 + 4) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(*piVar5 + 8) = *(undefined4 *)(param_1 + 0x14);
    if (*(char *)(iVar4 + 0x19) == '\0') {
      iVar1 = FUN_8002b9ec();
      *(undefined4 *)(*piVar5 + 0xc) = *(undefined4 *)(iVar1 + 0xc);
      *(float *)(*piVar5 + 0x10) = FLOAT_803e6bb8 + *(float *)(iVar1 + 0x10);
      *(undefined4 *)(*piVar5 + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    }
    FUN_8008f904(*piVar5);
    *(short *)(*piVar5 + 0x20) = *(short *)(*piVar5 + 0x20) + 1;
    if (*(ushort *)(*piVar5 + 0x22) <= *(ushort *)(*piVar5 + 0x20)) {
      FUN_80023800();
      *piVar5 = 0;
      *(byte *)(piVar5 + 1) = *(byte *)(piVar5 + 1) & 0x7f;
      if (*(int *)(iVar4 + 0x14) == -1) {
        *(byte *)(piVar5 + 1) = *(byte *)(piVar5 + 1) & 0xbf | 0x40;
      }
    }
  }
  else {
    if (*piVar5 != 0) {
      FUN_80023800();
      *piVar5 = 0;
    }
    uVar2 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x20));
    *(byte *)(piVar5 + 1) = (byte)((uVar2 & 0xff) << 7) | *(byte *)(piVar5 + 1) & 0x7f;
    if (*(char *)(piVar5 + 1) < '\0') {
      FUN_8000bb18(param_1,0x30f);
      local_3c = *(undefined4 *)(param_1 + 0xc);
      local_38 = *(undefined4 *)(param_1 + 0x10);
      local_34 = *(undefined4 *)(param_1 + 0x14);
      if ((*(char *)(iVar4 + 0x19) == 0) ||
         (iVar4 = FUN_80114184((int)*(char *)(iVar4 + 0x19),auStack48), iVar4 == 0)) {
        iVar4 = FUN_8002b9ec();
        local_48 = *(undefined4 *)(iVar4 + 0xc);
        local_44 = FLOAT_803e6bb8 + *(float *)(iVar4 + 0x10);
        local_40 = *(undefined4 *)(iVar4 + 0x14);
      }
      else {
        local_48 = local_24;
        local_44 = local_20;
        local_40 = local_1c;
      }
      uVar3 = FUN_800221a0(5,0xf);
      iVar4 = FUN_8008fb20((double)FLOAT_803e6bbc,(double)FLOAT_803e6bc0,&local_3c,&local_48,uVar3,
                           0x60,0);
      *piVar5 = iVar4;
    }
  }
  return;
}

