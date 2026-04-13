// Function: FUN_80220ea8
// Entry: 80220ea8
// Size: 528 bytes

void FUN_80220ea8(uint param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  undefined4 local_48;
  float local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined2 auStack_30 [6];
  undefined4 local_24;
  float local_20;
  undefined4 local_1c;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*(char *)(puVar4 + 1) < '\0') {
    *(undefined4 *)*puVar4 = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(*puVar4 + 4) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(*puVar4 + 8) = *(undefined4 *)(param_1 + 0x14);
    if (*(char *)(iVar3 + 0x19) == '\0') {
      iVar1 = FUN_8002bac4();
      *(undefined4 *)(*puVar4 + 0xc) = *(undefined4 *)(iVar1 + 0xc);
      *(float *)(*puVar4 + 0x10) = FLOAT_803e7850 + *(float *)(iVar1 + 0x10);
      *(undefined4 *)(*puVar4 + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    }
    FUN_8008fb90((float *)*puVar4);
    *(short *)(*puVar4 + 0x20) = *(short *)(*puVar4 + 0x20) + 1;
    uVar2 = *puVar4;
    if (*(ushort *)(uVar2 + 0x22) <= *(ushort *)(uVar2 + 0x20)) {
      FUN_800238c4(uVar2);
      *puVar4 = 0;
      *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 0x7f;
      if (*(int *)(iVar3 + 0x14) == -1) {
        *(byte *)(puVar4 + 1) = *(byte *)(puVar4 + 1) & 0xbf | 0x40;
      }
    }
  }
  else {
    if (*puVar4 != 0) {
      FUN_800238c4(*puVar4);
      *puVar4 = 0;
    }
    uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x20));
    *(byte *)(puVar4 + 1) = (byte)((uVar2 & 0xff) << 7) | *(byte *)(puVar4 + 1) & 0x7f;
    if (*(char *)(puVar4 + 1) < '\0') {
      FUN_8000bb38(param_1,0x30f);
      local_3c = *(undefined4 *)(param_1 + 0xc);
      local_38 = *(undefined4 *)(param_1 + 0x10);
      local_34 = *(undefined4 *)(param_1 + 0x14);
      if ((*(char *)(iVar3 + 0x19) == 0) ||
         (iVar3 = FUN_80114420((int)*(char *)(iVar3 + 0x19),auStack_30), iVar3 == 0)) {
        iVar3 = FUN_8002bac4();
        local_48 = *(undefined4 *)(iVar3 + 0xc);
        local_44 = FLOAT_803e7850 + *(float *)(iVar3 + 0x10);
        local_40 = *(undefined4 *)(iVar3 + 0x14);
      }
      else {
        local_48 = local_24;
        local_44 = local_20;
        local_40 = local_1c;
      }
      uVar2 = FUN_80022264(5,0xf);
      uVar2 = FUN_8008fdac((double)FLOAT_803e7854,(double)FLOAT_803e7858,&local_3c,&local_48,
                           (short)uVar2,0x60,0);
      *puVar4 = uVar2;
    }
  }
  return;
}

