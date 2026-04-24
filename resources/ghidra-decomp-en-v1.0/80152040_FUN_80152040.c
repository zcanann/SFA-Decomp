// Function: FUN_80152040
// Entry: 80152040
// Size: 672 bytes

void FUN_80152040(int param_1,int param_2)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((*(char *)(param_2 + 0x33a) == '\x02') &&
     (iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c)), iVar3 == 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      FUN_80151c68(param_1,param_2);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  if (((*(uint *)(param_2 + 0x2dc) & 0x80000000) != 0) &&
     (*(int *)(&DAT_8031f294 + (uint)*(byte *)(param_2 + 0x33a) * 0xc) != 0)) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    uVar1 = (uint)*(byte *)(param_2 + 0x33a);
    if (uVar1 == 0) {
      if ((*(uint *)(param_2 + 0x2dc) & 0x20000000) != 0) {
        iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c));
        if (iVar4 == 0) {
          *(undefined *)(param_2 + 0x33a) = (&DAT_8031f299)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
        }
        else {
          *(undefined *)(param_2 + 0x33a) = (&DAT_8031f29a)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
        }
      }
    }
    else if (uVar1 == 2) {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c));
      if ((iVar4 != 0) || ((*(uint *)(param_2 + 0x2dc) & 0x20000000) == 0)) {
        *(undefined *)(param_2 + 0x33a) = (&DAT_8031f299)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
      }
    }
    else if (uVar1 == 3) {
      iVar4 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1c));
      if (iVar4 == 0) {
        *(undefined *)(param_2 + 0x33a) = (&DAT_8031f299)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
      }
      else {
        *(undefined *)(param_2 + 0x33a) = (&DAT_8031f29a)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
      }
    }
    else {
      *(undefined *)(param_2 + 0x33a) = (&DAT_8031f299)[uVar1 * 0xc];
    }
    uVar2 = (ushort)(byte)(&DAT_8031f298)[(uint)*(byte *)(param_2 + 0x33a) * 0xc];
    if (*(ushort *)(param_1 + 0xa0) != uVar2) {
      if ((uVar2 != 0) && (uVar2 != 4)) {
        FUN_8000bb18(param_1,0x4a8);
      }
      iVar4 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
      FUN_8014d08c((double)*(float *)(&DAT_8031f290 + iVar4),param_1,param_2,(&DAT_8031f298)[iVar4],
                   0,0xf);
    }
  }
  if ((&DAT_8031f29b)[(uint)*(byte *)(param_2 + 0x33a) * 0xc] != '\0') {
    FUN_80151db8(param_1,param_2);
  }
  return;
}

